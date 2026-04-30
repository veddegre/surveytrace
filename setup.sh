#!/usr/bin/env bash
# =============================================================================
# SurveyTrace — Ubuntu setup script
# Tested on Ubuntu 24.04 LTS / 26.04 LTS
# Run as root:  sudo bash setup.sh
# =============================================================================
set -euo pipefail

# ---- Colour helpers ---------------------------------------------------------
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLU}[INFO]${NC}  $*"; }
ok()    { echo -e "${GRN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

# ---- Must be root -----------------------------------------------------------
[[ $EUID -eq 0 ]] || die "Run this script as root: sudo bash setup.sh"

# ---- Config (edit before running) ------------------------------------------
INSTALL_DIR="/opt/surveytrace"
DATA_DIR="${INSTALL_DIR}/data"
VENV_DIR="${INSTALL_DIR}/venv"
APP_USER="surveytrace"
WEB_GROUP="www-data"
PHP_MIN_VER="8.1"
PYTHON_MIN_VER="3.10"
WEB_SERVER=""   # leave blank to auto-detect (Apache preferred; nginx if already present)

# ---- Source dir (directory containing this script) -------------------------
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo -e "${BLU}╔══════════════════════════════════════════╗${NC}"
echo -e "${BLU}║        SurveyTrace — Setup Script        ║${NC}"
echo -e "${BLU}╚══════════════════════════════════════════╝${NC}"
echo ""

# =============================================================================
# STEP 1 — System packages
# =============================================================================
info "Updating package lists…"
apt-get update -qq

REQUIRED_PKGS=(
    # Core
    nmap
    python3
    python3-pip
    python3-venv
    python3-dev
    # PHP + SQLite
    php
    php-cli
    php-sqlite3
    php-json
    php-mbstring
    php-fpm
    # Build deps for scapy / python packages
    libssl-dev
    libffi-dev
    gcc
    # Misc
    git
    curl
    sqlite3
    qrencode        # required for local MFA QR generation
    samba-common-bin  # provides nmblookup (NetBIOS hostname fallback)
)

OPTIONAL_PKGS=(
    apache2         # default stack with setup.sh auto-install
    libapache2-mod-proxy-fcgi  # Apache + php-fpm (mod_php requires mpm_prefork; proxy_fcgi works with mpm_event)
    nginx           # optional alternative if you configure it manually
    tcpdump         # passive sniff fallback
    avahi-utils     # mDNS hostname resolution (avahi-resolve)
    avahi-daemon    # mDNS/Bonjour daemon
)

info "Installing required packages…"
apt-get install -y --no-install-recommends "${REQUIRED_PKGS[@]}" || \
    die "Failed to install required packages"
ok "Required packages installed"

# ---- PHP version check (before web server: vhost uses php${PHP_VER}-fpm socket) --
PHP_VER=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || echo "0.0")
if awk "BEGIN{exit !($PHP_VER >= $PHP_MIN_VER)}"; then
    ok "PHP $PHP_VER found (>= $PHP_MIN_VER required)"
else
    die "PHP $PHP_VER found but $PHP_MIN_VER+ required. Install php$PHP_MIN_VER from ppa:ondrej/php"
fi

# FPM socket path is /run/php/php${PHP_VER}-fpm.sock — install the versioned unit (not only meta php-fpm).
if apt-cache show "php${PHP_VER}-fpm" &>/dev/null; then
    apt-get install -y --no-install-recommends "php${PHP_VER}-fpm" || \
        warn "Could not install php${PHP_VER}-fpm — web server PHP may fail until it is installed"
fi

# Debian/Ubuntu: mod_proxy_fcgi lives here; package name is libapache2-mod-proxy-fcgi.
MOD_PROXY_FCGI_SO="/usr/lib/apache2/modules/mod_proxy_fcgi.so"
install_mod_proxy_fcgi() {
    if [[ -f "$MOD_PROXY_FCGI_SO" ]]; then
        return 0
    fi
    if apt-get install -y --no-install-recommends libapache2-mod-proxy-fcgi; then
        return 0
    fi
    info "apt could not install libapache2-mod-proxy-fcgi — refreshing package index and retrying…"
    apt-get update -qq && apt-get install -y --no-install-recommends libapache2-mod-proxy-fcgi && return 0
    return 1
}

# ---- Detect / install web server (Apache first; nginx only if already installed) --
if command -v apache2 &>/dev/null; then
    WEB_SERVER="apache2"
    ok "apache2 already present"
elif command -v nginx &>/dev/null; then
    WEB_SERVER="nginx"
    ok "nginx already present (no apache2 on host — using nginx)"
else
    info "Installing apache2 + mod_proxy_fcgi (PHP via php-fpm; works with mpm_event)…"
    apt-get install -y --no-install-recommends apache2 || die "Failed to install apache2"
    install_mod_proxy_fcgi || [[ -f "$MOD_PROXY_FCGI_SO" ]] || \
        die "mod_proxy_fcgi missing after apt (install libapache2-mod-proxy-fcgi or run apt-get update)"
    WEB_SERVER="apache2"
    ok "apache2 installed (PHP via php-fpm + proxy_fcgi)"
fi

# ---- Python version check ---------------------------------------------------
PYTHON_BIN=$(command -v python3.12 || command -v python3.11 || command -v python3.10 || command -v python3 || echo "")
[[ -n "$PYTHON_BIN" ]] || die "python3 not found"
PY_VER=$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if awk "BEGIN{exit !($PY_VER >= $PYTHON_MIN_VER)}"; then
    ok "Python $PY_VER found at $PYTHON_BIN (>= $PYTHON_MIN_VER required)"
else
    die "Python $PY_VER found but $PYTHON_MIN_VER+ required"
fi

# ---- nmap check -------------------------------------------------------------
NMAP_VER=$(nmap --version 2>/dev/null | head -1 | grep -oP '\d+\.\d+' | head -1 || echo "0")
ok "nmap $NMAP_VER found"

# =============================================================================
# STEP 2 — Create system user
# =============================================================================
if id "$APP_USER" &>/dev/null; then
    ok "User '$APP_USER' already exists"
else
    info "Creating system user '$APP_USER'…"
    useradd --system --no-create-home --shell /usr/sbin/nologin \
            --comment "SurveyTrace daemon" "$APP_USER"
    ok "User '$APP_USER' created"
fi

# Add web server user to app group so PHP can read the db dir
usermod -aG "$APP_USER" "$WEB_GROUP" 2>/dev/null || true

# =============================================================================
# STEP 3 — Install application files
# =============================================================================
info "Installing application to $INSTALL_DIR…"

if [[ "$SRC_DIR" != "$INSTALL_DIR" ]]; then
    # Ensure destination exists then copy contents (not the dir itself)
    # rsync preserves subdirectories reliably; fall back to explicit cp
    mkdir -p "$INSTALL_DIR"
    if command -v rsync &>/dev/null; then
        rsync -a --delete "$SRC_DIR/" "$INSTALL_DIR/"
    else
        # Explicit subdirectory copy — avoids scp/cp flattening issues.
        # Keep in sync with repo layout (api/ holds every PHP endpoint, including devices.php).
        for subdir in api daemon public sql docs; do
            if [[ -d "$SRC_DIR/$subdir" ]]; then
                mkdir -p "$INSTALL_DIR/$subdir"
                cp -r "$SRC_DIR/$subdir/." "$INSTALL_DIR/$subdir/"
            fi
        done
        # Copy root-level files
        find "$SRC_DIR" -maxdepth 1 -type f -exec cp {} "$INSTALL_DIR/" \;
    fi
    ok "Files copied to $INSTALL_DIR"
else
    ok "Already running from $INSTALL_DIR"
fi

# Create data dir (outside webroot)
mkdir -p "$DATA_DIR"

# =============================================================================
# STEP 4 — Python virtualenv + packages
# =============================================================================
info "Creating Python virtualenv at $VENV_DIR…"
$PYTHON_BIN -m venv "$VENV_DIR"
ok "Virtualenv created"

info "Installing Python dependencies…"
"$VENV_DIR/bin/pip" install --upgrade pip -q

PYTHON_PKGS=(
    "scapy>=2.5"
    "python-nmap>=0.7"
    "requests>=2.28"
    "pysnmp>=4.4"
)

for pkg in "${PYTHON_PKGS[@]}"; do
    info "  Installing $pkg…"
    "$VENV_DIR/bin/pip" install "$pkg" -q || warn "Failed to install $pkg — check manually"
done
ok "Python packages installed"

# Verify critical imports
"$VENV_DIR/bin/python3" -c "import nmap; import scapy; import requests; import pysnmp" 2>/dev/null && \
    ok "Python imports verified" || \
    warn "One or more Python imports failed — check $VENV_DIR/bin/pip list"

# =============================================================================
# STEP 5 — SQLite database bootstrap
# =============================================================================
DB_FILE="$DATA_DIR/surveytrace.db"
info "Bootstrapping SQLite database at $DB_FILE…"

SCHEMA_FILE="$INSTALL_DIR/sql/schema.sql"

# Fallback: if scp/cp flattened subdirs, schema.sql may be in the root
if [[ ! -f "$SCHEMA_FILE" && -f "$INSTALL_DIR/schema.sql" ]]; then
    warn "schema.sql found in root instead of sql/ — moving it to the correct location"
    mkdir -p "$INSTALL_DIR/sql"
    mv "$INSTALL_DIR/schema.sql" "$SCHEMA_FILE"
fi

[[ -f "$SCHEMA_FILE" ]] || die "schema.sql not found at $SCHEMA_FILE — ensure all subdirectories were copied"

mkdir -p "$DATA_DIR" || die "Cannot create data directory $DATA_DIR"

if [[ -f "$DB_FILE" ]]; then
    warn "Database already exists — skipping schema init (run with --reset to wipe)"
else
    sqlite3 "$DB_FILE" < "$SCHEMA_FILE" && ok "Schema applied" || \
        die "Failed to apply schema"
fi

# =============================================================================
# STEP 6 — Permissions
# =============================================================================
info "Setting permissions…"

# Root-own install tree, but never chown -R the whole $INSTALL_DIR including $DATA_DIR:
# that briefly makes surveytrace.db root:root and breaks daemons (sqlite: unable to open database file).
shopt -s nullglob
for item in "$INSTALL_DIR"/*; do
    [[ -e "$item" ]] || continue
    if [[ "$(readlink -f "$item")" == "$(readlink -f "$DATA_DIR")" ]]; then
        continue
    fi
    chown -R root:root "$item"
done
shopt -u nullglob

chown -R "$APP_USER":"$WEB_GROUP" "$DATA_DIR"
chmod 770 "$DATA_DIR"
chmod g+s "$DATA_DIR"
[[ -f "$DB_FILE" ]] && chmod 660 "$DB_FILE" && chown "$APP_USER":"$WEB_GROUP" "$DB_FILE"

# PHP can read/write db via www-data group
chmod 750 "$INSTALL_DIR/api"
chown -R root:"$WEB_GROUP" "$INSTALL_DIR/api"
chmod 750 "$INSTALL_DIR/public"
chown -R root:"$WEB_GROUP" "$INSTALL_DIR/public"

# Daemon scripts: readable by app user
chmod 750 "$INSTALL_DIR/daemon"
chown -R "$APP_USER":"$APP_USER" "$INSTALL_DIR/daemon"

# Existing files should be writable by both daemon user + web group
find "$DATA_DIR" -type d -exec chmod 2770 {} \; 2>/dev/null || true
find "$DATA_DIR" -type f -exec chmod 660 {} \; 2>/dev/null || true

ok "Permissions set"

# =============================================================================
# STEP 7 — systemd services (scanner daemon + scheduler daemon)
# =============================================================================

install_service() {
    local svc_name="$1"
    local svc_src="$INSTALL_DIR/${svc_name}.service"
    local svc_dest="/etc/systemd/system/${svc_name}.service"

    if [[ -f "$svc_src" ]]; then
        info "Installing $svc_name…"
        sed -e "s|/opt/surveytrace|$INSTALL_DIR|g" \
            -e "s|User=surveytrace|User=$APP_USER|g" \
            "$svc_src" > "$svc_dest"
        systemctl daemon-reload
        [[ -f "$DB_FILE" ]] || die "Database missing at $DB_FILE — refusing to start $svc_name (bootstrap step failed?)"
        if command -v runuser &>/dev/null; then
            runuser -u "$APP_USER" -- sqlite3 "$DB_FILE" "SELECT 1;" >/dev/null \
                || die "Database not readable as $APP_USER — fix ownership on $DATA_DIR (see STEP 6)"
        else
            sudo -u "$APP_USER" sqlite3 "$DB_FILE" "SELECT 1;" >/dev/null \
                || die "Database not readable as $APP_USER — fix ownership on $DATA_DIR (see STEP 6)"
        fi
        systemctl enable "$svc_name"
        systemctl start  "$svc_name"
        sleep 2
        if systemctl is-active --quiet "$svc_name"; then
            ok "$svc_name is running"
        else
            warn "$svc_name failed to start — check: journalctl -u $svc_name -n 50"
        fi
    else
        warn "Service file not found at $svc_src — skipping"
    fi
}

install_service "surveytrace-daemon"
install_service "surveytrace-scheduler"

# =============================================================================
# STEP 8 — Web server config
# =============================================================================
WEBROOT="$INSTALL_DIR/public"

if [[ "$WEB_SERVER" == "nginx" ]]; then
    # nginx matches the first regex location in file order; a generic "~ \.php$"
    # must NOT win for /api/*.php or PHP is looked up under DocumentRoot/public and
    # raw source or 404 can result. Nested "location /api/" + fastcgi-php.conf try_files
    # also breaks with alias — use an explicit API regex before the generic PHP block.
    NGINX_CONF="/etc/nginx/sites-available/surveytrace"
    cat > "$NGINX_CONF" <<NGINX
server {
    listen 80;
    server_name _;
    root $WEBROOT;
    index index.php;

    # Block direct access to sensitive dirs
    location ~ ^/(data|sql|daemon|venv)/ { deny all; }

    # API PHP — must precede generic "~ \.php\$" (do not use fastcgi-php.conf here:
    # its try_files is wrong for alias-style paths outside root).
    location ~ ^/api/(.+\.php)\$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $INSTALL_DIR/api/\$1;
        fastcgi_pass unix:/run/php/php${PHP_VER}-fpm.sock;
    }

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${PHP_VER}-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }

    access_log /var/log/nginx/surveytrace_access.log;
    error_log  /var/log/nginx/surveytrace_error.log;
}
NGINX
    ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/surveytrace
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    nginx -t && systemctl reload nginx && ok "nginx configured and reloaded" || \
        warn "nginx config test failed — check $NGINX_CONF"

elif [[ "$WEB_SERVER" == "apache2" ]]; then
    # Use php-fpm + mod_proxy_fcgi (default mpm_event works). libapache2-mod-php only runs under
    # mpm_prefork; with mpm_event it often stays unloaded and Apache serves .php as literal source.
    info "Configuring Apache with php-fpm (proxy_fcgi)…"
    apt-get install -y --no-install-recommends apache2 || die "Failed to install apache2"
    install_mod_proxy_fcgi || [[ -f "$MOD_PROXY_FCGI_SO" ]] || \
        die "mod_proxy_fcgi missing (install libapache2-mod-proxy-fcgi; on stale mirrors: apt-get update)"
    mkdir -p /etc/apache2/sites-available
    if apt-cache show "php${PHP_VER}-fpm" &>/dev/null; then
        apt-get install -y --no-install-recommends "php${PHP_VER}-fpm" || \
            warn "Could not install php${PHP_VER}-fpm"
    fi
    # FPM must be listening before Apache proxies (socket below).
    if systemctl list-unit-files "php${PHP_VER}-fpm.service" &>/dev/null; then
        systemctl enable "php${PHP_VER}-fpm" && systemctl start "php${PHP_VER}-fpm" || \
            warn "php${PHP_VER}-fpm failed to start — Apache PHP will fail until FPM runs"
    else
        warn "php${PHP_VER}-fpm unit missing — install php${PHP_VER}-fpm (must match: php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;')"
    fi
    a2dismod php${PHP_VER} 2>/dev/null || true
    a2enmod proxy proxy_fcgi setenvif rewrite 2>/dev/null || true
    APACHE_CONF="/etc/apache2/sites-available/surveytrace.conf"
    cat > "$APACHE_CONF" <<APACHE
<VirtualHost *:80>
    DocumentRoot $WEBROOT
    DirectoryIndex index.php

    Alias /api $INSTALL_DIR/api
    <Directory $INSTALL_DIR/api>
        Options -Indexes
        AllowOverride None
        Require all granted
        <FilesMatch "\.php\$">
            SetHandler "proxy:unix:/run/php/php${PHP_VER}-fpm.sock|fcgi://localhost"
        </FilesMatch>
    </Directory>

    <Directory $WEBROOT>
        Options -Indexes
        AllowOverride All
        Require all granted
        <FilesMatch "\.php\$">
            SetHandler "proxy:unix:/run/php/php${PHP_VER}-fpm.sock|fcgi://localhost"
        </FilesMatch>
    </Directory>

    # Block sensitive dirs
    <DirectoryMatch "^$INSTALL_DIR/(data|sql|daemon|venv)">
        Require all denied
    </DirectoryMatch>

    ErrorLog  \${APACHE_LOG_DIR}/surveytrace_error.log
    CustomLog \${APACHE_LOG_DIR}/surveytrace_access.log combined
</VirtualHost>
APACHE
    a2ensite surveytrace
    a2dissite 000-default 2>/dev/null || true
    if apache2ctl configtest 2>/dev/null; then
        systemctl restart apache2 && ok "apache2 configured and restarted (php-fpm via proxy_fcgi)" || \
            warn "apache2 restart failed — check $APACHE_CONF and journalctl -u apache2"
    else
        warn "apache2 config test failed — check $APACHE_CONF"
    fi
fi

# ---- PHP-FPM ---------------------------------------------------------------
PHP_FPM_SVC="php${PHP_VER}-fpm"
if systemctl list-unit-files "$PHP_FPM_SVC.service" &>/dev/null; then
    systemctl enable "$PHP_FPM_SVC" && systemctl start "$PHP_FPM_SVC"
    ok "$PHP_FPM_SVC running"
else
    warn "php-fpm service not found — install php${PHP_VER}-fpm manually if using nginx"
fi

# =============================================================================
# STEP 9 — Capability grant for raw sockets (nmap/scapy)
# =============================================================================
info "Granting CAP_NET_RAW to nmap binary…"
NMAP_BIN=$(command -v nmap)
if [[ -n "$NMAP_BIN" ]]; then
    setcap cap_net_raw,cap_net_admin+eip "$NMAP_BIN" && ok "Capabilities set on nmap" || \
        warn "setcap failed — daemon may need to run as root for raw scanning"
fi

PYTHON3_BIN="$VENV_DIR/bin/python3"
if [[ -f "$PYTHON3_BIN" ]]; then
    PYTHON3_REAL=$(readlink -f "$PYTHON3_BIN")
    setcap cap_net_raw,cap_net_admin+eip "$PYTHON3_REAL" && ok "Capabilities set on venv python3 ($PYTHON3_REAL)" || \
        warn "setcap on python3 failed — scapy passive sniff may not work as non-root"
fi

# =============================================================================
# STEP 10 — Initial NVD sync prompt
# =============================================================================
echo ""
info "Optional NIST NVD API key (much faster full sync + weekly updates)."
echo "  Request a free key: https://nvd.nist.gov/developers/request-an-api-key"
read -rsp "Paste key here (input hidden), or press Enter to skip: " nvd_key_choice
echo ""
# Trim leading/trailing whitespace (NIST keys are UUID-like; no spaces expected)
nvd_key_choice="${nvd_key_choice#"${nvd_key_choice%%[![:space:]]*}"}"
nvd_key_choice="${nvd_key_choice%"${nvd_key_choice##*[![:space:]]}"}"
nvd_key_choice="${nvd_key_choice//$'\r'/}"
if [[ -n "$nvd_key_choice" ]]; then
    if [[ ${#nvd_key_choice} -ge 30 && ${#nvd_key_choice} -le 128 ]] && [[ "$nvd_key_choice" =~ ^[A-Za-z0-9-]+$ ]]; then
        nvd_esc=${nvd_key_choice//\'/\'\'}
        if sudo -u "$APP_USER" sqlite3 "$DB_FILE" "INSERT OR REPLACE INTO config (key, value) VALUES ('nvd_api_key', '$nvd_esc');"; then
            ok "NVD API key saved to config (same as Settings → NVD)"
        else
            warn "Could not save NVD API key to database — add it later in Settings"
        fi
    else
        warn "NVD API key not saved (expect 30–128 chars: letters, digits, hyphens only)"
    fi
fi

echo ""
echo -e "${YLW}┌─────────────────────────────────────────────────────┐${NC}"
printf "${YLW}│%-53s│${NC}\n" "  NVD CVE database - first-time full catalog sync    "
printf "${YLW}│%-53s│${NC}\n" "  First run: full NVD CVE catalog import (~1+ GB).   "
printf "${YLW}│%-53s│${NC}\n" "  Download is large; plan hours without an API key.  "
printf "${YLW}│%-53s│${NC}\n" "  With NVD API key: often ~20-60+ minutes instead.   "
printf "${YLW}│%-53s│${NC}\n" "  Add key in Settings (README: NVD Database Setup).  "
echo -e "${YLW}└─────────────────────────────────────────────────────┘${NC}"
read -rp "Run NVD sync now? [y/N] " run_nvd
if [[ "${run_nvd,,}" == "y" ]]; then
    info "Running NVD full sync (often 20+ min with API key; much longer without)…"
    sudo -u "$APP_USER" "$VENV_DIR/bin/python3" "$INSTALL_DIR/daemon/sync_nvd.py" && \
        ok "NVD sync complete" || warn "NVD sync encountered errors — retry with: sudo -u $APP_USER $VENV_DIR/bin/python3 $INSTALL_DIR/daemon/sync_nvd.py"
else
    info "Skipping NVD sync. Run manually when ready:"
    echo "  sudo -u $APP_USER $VENV_DIR/bin/python3 $INSTALL_DIR/daemon/sync_nvd.py"
fi

# =============================================================================
# STEP 11 — External fingerprint feed sync prompt (OUI + Web app signatures)
# =============================================================================
echo ""
echo -e "${YLW}┌─────────────────────────────────────────────────────┐${NC}"
echo -e "${YLW}│  Fingerprint feed sync                              │${NC}"
echo -e "${YLW}│  Pulls IEEE OUI + Wappalyzer rules into data/.      │${NC}"
echo -e "${YLW}└─────────────────────────────────────────────────────┘${NC}"
read -rp "Run OUI/Web fingerprint sync now? [y/N] " run_fp
if [[ "${run_fp,,}" == "y" ]]; then
    info "Running OUI sync…"
    sudo -u "$APP_USER" "$VENV_DIR/bin/python3" "$INSTALL_DIR/daemon/sync_oui.py" && \
        ok "OUI sync complete" || warn "OUI sync failed — retry manually"
    info "Running web fingerprint sync…"
    sudo -u "$APP_USER" "$VENV_DIR/bin/python3" "$INSTALL_DIR/daemon/sync_webfp.py" && \
        ok "Web fingerprint sync complete" || warn "Web fingerprint sync failed — retry manually"
else
    info "Skipping fingerprint sync. Run manually when ready:"
    echo "  sudo -u $APP_USER $VENV_DIR/bin/python3 $INSTALL_DIR/daemon/sync_oui.py"
    echo "  sudo -u $APP_USER $VENV_DIR/bin/python3 $INSTALL_DIR/daemon/sync_webfp.py"
fi

# =============================================================================
# STEP 12 — Set web UI password
# =============================================================================
echo ""
info "Set a web UI login password (leave blank to skip and set later):"
read -rsp "Password: " UI_PASS
echo ""

if [[ -n "$UI_PASS" ]]; then
    # Pass password via env — embedding \$UI_PASS in php -r breaks on quotes, \$, etc.
    HASH=$(UI_PASS="$UI_PASS" php -r '$p = getenv("UI_PASS"); echo password_hash($p, PASSWORD_ARGON2ID);')
    sqlite3 "$DB_FILE" "UPDATE config SET value='$HASH' WHERE key='auth_hash';"
    ok "Web UI password set"
else
    warn "No password set — UI is open. Set one via:"
    echo "  HASH=\$(UI_PASS='YOURPASS' php -r '\$p = getenv(\"UI_PASS\"); echo password_hash(\$p, PASSWORD_ARGON2ID);')"
    echo "  sqlite3 $DB_FILE \"UPDATE config SET value='\$HASH' WHERE key='auth_hash';\""
fi

# =============================================================================
# STEP 13 — Scheduled feed refresh (NVD + fingerprint feeds)
# =============================================================================
CRON_FILE="/etc/cron.d/surveytrace-nvd"
cat > "$CRON_FILE" <<CRON
# SurveyTrace — weekly NVD CVE feed refresh (Sunday 3am)
0 3 * * 0 $APP_USER $VENV_DIR/bin/python3 $INSTALL_DIR/daemon/sync_nvd.py --recent >> $DATA_DIR/nvd_sync.log 2>&1
CRON
chmod 644 "$CRON_FILE"
ok "Weekly NVD cron installed at $CRON_FILE"

FP_CRON_FILE="/etc/cron.d/surveytrace-fp"
cat > "$FP_CRON_FILE" <<CRON
# SurveyTrace — daily OUI + web fingerprint feed refresh
15 4 * * * $APP_USER $VENV_DIR/bin/python3 $INSTALL_DIR/daemon/sync_oui.py >> $DATA_DIR/oui_sync.log 2>&1
30 4 * * * $APP_USER $VENV_DIR/bin/python3 $INSTALL_DIR/daemon/sync_webfp.py >> $DATA_DIR/webfp_sync.log 2>&1
CRON
chmod 644 "$FP_CRON_FILE"
ok "Daily fingerprint feed cron installed at $FP_CRON_FILE"

# =============================================================================
# STEP 14 — UFW firewall (LAN-safe defaults)
# =============================================================================
if command -v ufw &>/dev/null; then
    info "Configuring UFW firewall…"
else
    info "Installing UFW…"
    apt-get install -y --no-install-recommends ufw
fi

# Detect primary LAN interface and subnet for the allow rule
LAN_IFACE=$(ip route | awk '/default/ {print $5; exit}')
LAN_SUBNET=$(ip -o -f inet addr show "$LAN_IFACE" 2>/dev/null | \
    awk '{print $4}' | head -1)

# Reset to clean state without prompting
ufw --force reset > /dev/null 2>&1

# Defaults — deny all incoming, allow all outgoing
ufw default deny incoming  > /dev/null
ufw default allow outgoing > /dev/null

# SSH — allow from LAN subnet only if detectable, otherwise allow all
# (prevents lockout if running over SSH)
if [[ -n "$LAN_SUBNET" ]]; then
    ufw allow from "$LAN_SUBNET" to any port 22  proto tcp comment 'SSH from LAN'   > /dev/null
    ufw allow from "$LAN_SUBNET" to any port 80  proto tcp comment 'HTTP from LAN'  > /dev/null
    ufw allow from "$LAN_SUBNET" to any port 443 proto tcp comment 'HTTPS from LAN' > /dev/null
    ok "UFW rules: SSH/HTTP/HTTPS restricted to $LAN_SUBNET"
else
    ufw allow 22/tcp  comment 'SSH'   > /dev/null
    ufw allow 80/tcp  comment 'HTTP'  > /dev/null
    ufw allow 443/tcp comment 'HTTPS' > /dev/null
    warn "Could not detect LAN subnet — SSH/HTTP open to all interfaces"
fi

# Allow outbound scanning traffic (needed for nmap/scapy raw sockets)
# These are outgoing so covered by default allow outgoing, but be explicit
# ICMP outbound is covered by 'default allow outgoing' — no explicit rule needed

ufw --force enable > /dev/null
ok "UFW enabled"
ufw status numbered

# =============================================================================
# Summary
# =============================================================================
SERVER_IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${GRN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GRN}║  SurveyTrace installation complete                   ║${NC}"
echo -e "${GRN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${GRN}║${NC}  Web UI:      http://${SERVER_IP}/                     "
echo -e "${GRN}║${NC}  Install dir: $INSTALL_DIR                          "
echo -e "${GRN}║${NC}  Database:    $DB_FILE               "
echo -e "${GRN}║${NC}  Daemon log:  $DATA_DIR/daemon.log              "
echo -e "${GRN}║${NC}  Daemon svc:  systemctl status surveytrace-daemon    "
echo -e "${GRN}║${NC}  Scheduler:   systemctl status surveytrace-scheduler  "
echo -e "${GRN}║${NC}  Firewall:    ufw status numbered                     "
echo -e "${GRN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Daemon status:  systemctl status surveytrace-daemon"
echo "  Daemon logs:    journalctl -u surveytrace-daemon -f"
echo "  NVD sync:       sudo -u $APP_USER $VENV_DIR/bin/python3 $INSTALL_DIR/daemon/sync_nvd.py"
echo "  Firewall:       ufw status numbered"
echo "  Add LAN rule:   ufw allow from 192.168.x.0/24 to any port 80 proto tcp"
echo ""
