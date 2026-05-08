#!/usr/bin/env bash
# =============================================================================
# SurveyTrace — Ubuntu setup script
# Tested on Ubuntu 24.04 LTS / 26.04 LTS
# Run as root:  sudo bash setup.sh
# You will be asked: full server (1) or collector-only (2). Non-interactive:
#   SURVEYTRACE_SETUP=master|collector
# =============================================================================
set -euo pipefail

# ---- Colour helpers ---------------------------------------------------------
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLU}[INFO]${NC}  $*"; }
ok()    { echo -e "${GRN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

CHECK_FAIL=0
CHECK_WARN=0
check_ok()   { echo -e "${GRN}[ OK ]${NC}  $*"; }
check_warn() { echo -e "${YLW}[WARN]${NC}  $*"; CHECK_WARN=$((CHECK_WARN + 1)); }
check_fail() { echo -e "${RED}[FAIL]${NC}  $*"; CHECK_FAIL=$((CHECK_FAIL + 1)); }

check_file() {
    local p="$1" label="$2"
    [[ -f "$p" ]] && check_ok "$label" || check_fail "$label (missing: $p)"
}
check_dir() {
    local p="$1" label="$2"
    [[ -d "$p" ]] && check_ok "$label" || check_fail "$label (missing: $p)"
}
check_owner_group() {
    local p="$1" want="$2" label="$3"
    local got
    got=$(stat -c '%U:%G' "$p" 2>/dev/null || echo "missing")
    [[ "$got" == "$want" ]] && check_ok "$label" || check_fail "$label (got $got, want $want)"
}
check_mode() {
    local p="$1" want="$2" label="$3"
    local got
    got=$(stat -c '%a' "$p" 2>/dev/null || echo "missing")
    [[ "$got" == "$want" ]] && check_ok "$label" || check_fail "$label (got $got, want $want)"
}
check_readable_as_user() {
    local user="$1" p="$2" label="$3"
    if runuser -u "$user" -- test -r "$p" >/dev/null 2>&1; then
        check_ok "$label"
    else
        check_fail "$label (not readable by $user: $p)"
    fi
}
check_executable_as_user() {
    local user="$1" p="$2" label="$3"
    if runuser -u "$user" -- test -x "$p" >/dev/null 2>&1; then
        check_ok "$label"
    else
        check_fail "$label (not executable by $user: $p)"
    fi
}
check_systemd_unit_present() {
    local unit="$1"
    if systemctl cat "$unit" >/dev/null 2>&1; then
        check_ok "systemd unit present: $unit"
    else
        check_fail "systemd unit missing: $unit"
    fi
}
check_systemd_unit_enabled() {
    local unit="$1"
    if systemctl is-enabled "$unit" >/dev/null 2>&1; then
        check_ok "systemd unit enabled: $unit"
    else
        check_warn "systemd unit not enabled: $unit"
    fi
}
check_systemd_unit_rw_policy() {
    local unit="$1"
    local cat_out
    cat_out="$(systemctl cat "$unit" 2>/dev/null || true)"
    if printf '%s\n' "$cat_out" | grep -Eq '^ProtectSystem=strict'; then
        if printf '%s\n' "$cat_out" | grep -Eq '^ReadWritePaths=.*/data'; then
            check_ok "systemd unit strict+ReadWritePaths data: $unit"
        else
            check_fail "systemd unit uses ProtectSystem=strict but lacks ReadWritePaths=/opt/surveytrace/data: $unit"
        fi
    else
        check_ok "systemd unit RW policy acceptable (no ProtectSystem=strict): $unit"
    fi
}
check_systemd_unit_has_line() {
    local unit="$1" regex="$2" label="$3"
    if systemctl cat "$unit" 2>/dev/null | grep -Eq "$regex"; then
        check_ok "$label"
    else
        check_fail "$label"
    fi
}

st_php_cli_is_safe_path() {
    local p="$1"
    [[ "$p" =~ ^/(usr/bin|usr/local/bin)/php([0-9.]+)?$ ]]
}

st_php_cli_is_candidate_ok() {
    local p="$1"
    [[ -n "$p" ]] || return 1
    st_php_cli_is_safe_path "$p" || return 1
    [[ -x "$p" ]] || return 1
    local sapi
    sapi="$("$p" -r 'echo PHP_SAPI, PHP_EOL;' 2>/dev/null | tr -d '\r\n' || true)"
    [[ "$sapi" == "cli" ]]
}

st_detect_php_cli_bin() {
    local candidate=""
    if [[ -n "${SURVEYTRACE_PHP_CLI_BIN:-}" ]] && st_php_cli_is_candidate_ok "${SURVEYTRACE_PHP_CLI_BIN}"; then
        printf '%s\n' "${SURVEYTRACE_PHP_CLI_BIN}"
        return 0
    fi
    candidate="$(command -v php 2>/dev/null || true)"
    if st_php_cli_is_candidate_ok "$candidate"; then
        printf '%s\n' "$candidate"
        return 0
    fi
    for candidate in /usr/bin/php /usr/local/bin/php; do
        if st_php_cli_is_candidate_ok "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    local matches=()
    local f=""
    shopt -s nullglob
    matches=(/usr/bin/php[0-9.]*)
    shopt -u nullglob
    if [[ "${#matches[@]}" -gt 0 ]]; then
        IFS=$'\n' matches=($(printf '%s\n' "${matches[@]}" | sort -V -r))
        unset IFS
        for f in "${matches[@]}"; do
            if st_php_cli_is_candidate_ok "$f"; then
                printf '%s\n' "$f"
                return 0
            fi
        done
    fi
    return 1
}

st_upsert_env_kv() {
    local env_file="$1"
    local key="$2"
    local value="$3"
    install -d -m 750 /etc/surveytrace
    [[ -f "$env_file" ]] || install -m 600 /dev/null "$env_file"
    if grep -Eq "^${key}=" "$env_file"; then
        sed -i "s|^${key}=.*$|${key}=${value}|" "$env_file"
    else
        printf '%s=%s\n' "$key" "$value" >> "$env_file"
    fi
    chown root:surveytrace /etc/surveytrace
    chmod 750 /etc/surveytrace
    chown root:surveytrace "$env_file"
    chmod 640 "$env_file"
}

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

# ---- Full server vs collector (prompt or SURVEYTRACE_SETUP) -----------------
# Interactive: choose at the start. Non-TTY (e.g. cloud-init): set
#   SURVEYTRACE_SETUP=master   — full stack (this script continues)
#   SURVEYTRACE_SETUP=collector — runs collector/setup.sh and exits
_setup_env_lower="$(printf '%s' "${SURVEYTRACE_SETUP:-}" | tr '[:upper:]' '[:lower:]')"
SETUP_MODE=""
case "$_setup_env_lower" in
    master|full|server) SETUP_MODE="master" ;;
    collector|agent) SETUP_MODE="collector" ;;
    "")
        if [[ -t 0 ]] && [[ -t 1 ]]; then
            echo ""
            echo -e "${BLU}SurveyTrace — choose install type${NC}"
            echo "  1) Full SurveyTrace server (web UI, API, daemons, database)"
            echo "  2) Collector only (remote scan node; pairs with your SurveyTrace server)"
            echo ""
            read -r -p "Enter 1 or 2 [1]: " _setup_choice || true
            _setup_choice="$(printf '%s' "${_setup_choice:-1}" | tr -d '[:space:]')"
            [[ -z "$_setup_choice" ]] && _setup_choice=1
            case "$_setup_choice" in
                1) SETUP_MODE="master" ;;
                2) SETUP_MODE="collector" ;;
                *) die "Invalid choice: ${_setup_choice} — enter 1 or 2" ;;
            esac
        else
            die "Cannot show install menu (stdin/stdout is not a terminal). Run: SURVEYTRACE_SETUP=master sudo bash setup.sh  or  SURVEYTRACE_SETUP=collector sudo bash setup.sh"
        fi
        ;;
    *)
        die "SURVEYTRACE_SETUP must be master or collector (got: ${SURVEYTRACE_SETUP})"
        ;;
esac
unset _setup_env_lower

if [[ "$SETUP_MODE" == "collector" ]]; then
    info "Starting collector setup (collector/setup.sh)…"
    exec bash "$SRC_DIR/collector/setup.sh"
fi

# ---- Install role guard (full stack vs collector-only) ---------------------
# Writes $DATA_DIR/.install_role at end. Refuse full setup on collector nodes.
INSTALL_ROLE_FILE="$DATA_DIR/.install_role"
skip_install_role_check() { [[ "${SURVEYTRACE_SKIP_INSTALL_ROLE_CHECK:-}" == 1 ]]; }
if ! skip_install_role_check; then
    role=""
    [[ -f "$INSTALL_ROLE_FILE" ]] && role=$(tr -d '[:space:]' < "$INSTALL_ROLE_FILE" 2>/dev/null || true)
    if [[ "$role" == "collector" ]]; then
        die "This host is marked collector-only ($INSTALL_ROLE_FILE). Do not run the full master setup.sh here. Use: sudo bash \"$SRC_DIR/collector/setup.sh\" or bash \"$SRC_DIR/collector/deploy.sh\". Override (emergency only): SURVEYTRACE_SKIP_INSTALL_ROLE_CHECK=1"
    fi
    if [[ "$role" != "master" ]] && [[ -f /etc/surveytrace/collector.json ]] && [[ -f /etc/systemd/system/surveytrace-collector.service ]] \
        && [[ ! -f "$INSTALL_DIR/api/db.php" ]]; then
        die "This host looks like a SurveyTrace collector (collector.json + surveytrace-collector unit, no $INSTALL_DIR/api/db.php). Do not run the full master setup.sh. Use collector/setup.sh or collector/deploy.sh. If this is wrong, set SURVEYTRACE_SKIP_INSTALL_ROLE_CHECK=1 or remove the mistaken collector files."
    fi
fi

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
    php-curl
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

# cURL extension for the same PHP version (Zabbix, integrations, AI HTTP); meta php-curl may lag behind PHP_VER.
if apt-cache show "php${PHP_VER}-curl" &>/dev/null; then
    apt-get install -y --no-install-recommends "php${PHP_VER}-curl" || \
        warn "Could not install php${PHP_VER}-curl — HTTP client features may fail until it is installed"
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
    # rsync preserves subdirectories reliably; fall back to explicit cp.
    # Excludes avoid overwriting runtime dirs (.venv/data), secrets, local DBs, and SCM junk — mirrors deploy.sh manifest discipline (do not rsync blind "*" without guards).
    mkdir -p "$INSTALL_DIR"
    if command -v rsync &>/dev/null; then
        RSYNC_EXCLUDES=(
            '--exclude=.git/'
            '--exclude=.cursor/'
            '--exclude=.vscode/'
            '--exclude=data/'
            '--exclude=venv/'
            '--exclude=.env'
            '--exclude=*.db'
            '--exclude=*.db-shm'
            '--exclude=*.db-wal'
            '--exclude=__pycache__/'
            '--exclude=*.pyc'
            '--exclude=config.local.php'
        )
        rsync -a --delete "${RSYNC_EXCLUDES[@]}" "$SRC_DIR/" "$INSTALL_DIR/"
    else
        # Explicit subdirectory copy — avoids scp/cp flattening issues.
        # Keep in sync with repo layout (api/ holds every PHP endpoint, including devices.php).
        # docs/ includes operator reference (e.g. TRUSTED_DATA_MODEL.md, CREDENTIALED_CHECKS_*.md).
        # scripts/ ships maintenance CLIs + production selftests (see scripts/deploy_file_manifest.php).
        for subdir in api daemon public sql docs scripts; do
            if [[ -d "$SRC_DIR/$subdir" ]]; then
                mkdir -p "$INSTALL_DIR/$subdir"
                cp -r "$SRC_DIR/$subdir/." "$INSTALL_DIR/$subdir/"
            fi
        done
        # Copy root-level files (VERSION, *.service, etc.)
        find "$SRC_DIR" -maxdepth 1 -type f -exec cp {} "$INSTALL_DIR/" \;
    fi
    ok "Files copied to $INSTALL_DIR"
else
    ok "Already running from $INSTALL_DIR"
fi

if command -v php >/dev/null 2>&1 && [[ -f "$INSTALL_DIR/scripts/check_deploy_coverage.php" ]]; then
    php "$INSTALL_DIR/scripts/check_deploy_coverage.php" "$INSTALL_DIR" || die "Deploy/manifest coverage check failed — fix scripts/deploy_file_manifest.php or repo layout"
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
    "paramiko>=3.0"
)

for pkg in "${PYTHON_PKGS[@]}"; do
    info "  Installing $pkg…"
    "$VENV_DIR/bin/pip" install "$pkg" -q || warn "Failed to install $pkg — check manually"
done
ok "Python packages installed"

# Verify critical imports
"$VENV_DIR/bin/python3" -c "import nmap; import scapy; import requests; import pysnmp; import paramiko" 2>/dev/null && \
    ok "Python imports verified" || \
    warn "One or more Python imports failed — check $VENV_DIR/bin/pip list"

# =============================================================================
# STEP 5 — SQLite database bootstrap
# =============================================================================
# Fresh installs: sql/schema.sql includes asset lifecycle columns on assets.
# Existing installs: api/db.php migrations apply on first PHP connection.
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

# api/: owned by surveytrace so scheduler (User=surveytrace) can read PHP CLI workers
# (e.g. zabbix_sync_worker.php, zabbix_output_worker.php, reporting_cli.php). www-data
# reads via group bit; dirs 2750 so new files under api/ inherit www-data group when
# created by surveytrace. Not world-readable.
chown -R "$APP_USER":"$WEB_GROUP" "$INSTALL_DIR/api"
chmod 2750 "$INSTALL_DIR/api"
find "$INSTALL_DIR/api" -type d -exec chmod 2750 {} \; 2>/dev/null || true
find "$INSTALL_DIR/api" -type f -exec chmod 640 {} \; 2>/dev/null || true

chmod 750 "$INSTALL_DIR/public"
chown -R root:"$WEB_GROUP" "$INSTALL_DIR/public"

# Daemon scripts: readable by app user
chmod 750 "$INSTALL_DIR/daemon"
chown -R "$APP_USER":"$APP_USER" "$INSTALL_DIR/daemon"

# Existing files should be writable by both daemon user + web group
find "$DATA_DIR" -type d -exec chmod 2770 {} \; 2>/dev/null || true
find "$DATA_DIR" -type f -exec chmod 660 {} \; 2>/dev/null || true

# WAL sidecars (created when SQLite uses journal_mode=WAL): must stay owned like surveytrace.db
# so both surveytrace daemons and www-data (group) can read/write. Directory setgid (2770) applies
# to new files; fix any pre-existing wal/shm from a manual copy or interrupted run.
for _walpair in "$DB_FILE-wal" "$DB_FILE-shm"; do
    if [[ -e "$_walpair" ]]; then
        chown "$APP_USER":"$WEB_GROUP" "$_walpair" 2>/dev/null || true
        chmod 660 "$_walpair" 2>/dev/null || true
    fi
done

printf '%s\n' master > "$INSTALL_ROLE_FILE"
chown "$APP_USER":"$WEB_GROUP" "$INSTALL_ROLE_FILE"
chmod 660 "$INSTALL_ROLE_FILE"

ok "Permissions set"

# =============================================================================
# STEP 7 — systemd services (scanner + scheduler + collector ingest on master)
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
install_service "surveytrace-collector-ingest"
install_service "surveytrace-credential-check-worker"

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
echo ""
info "Running post-install validation…"

check_dir "$INSTALL_DIR" "Install root exists"
check_dir "$INSTALL_DIR/api" "api/ exists"
check_dir "$INSTALL_DIR/public" "public/ exists"
check_dir "$INSTALL_DIR/daemon" "daemon/ exists"
check_dir "$INSTALL_DIR/data" "data/ exists"

check_owner_group "$INSTALL_DIR/api" "$APP_USER:$WEB_GROUP" "api owner/group"
check_mode "$INSTALL_DIR/api" "2750" "api directory mode"
check_owner_group "$INSTALL_DIR/data" "$APP_USER:$WEB_GROUP" "data owner/group"
check_mode "$INSTALL_DIR/data" "2770" "data directory mode"

check_file "$INSTALL_DIR/docs/TRUSTED_DATA_MODEL.md" "docs/TRUSTED_DATA_MODEL.md exists"
check_file "$INSTALL_DIR/docs/CREDENTIALED_CHECKS_ENGINE.md" "docs/CREDENTIALED_CHECKS_ENGINE.md exists"
check_file "$INSTALL_DIR/docs/CREDENTIALED_CHECKS_MVP_PLAN.md" "docs/CREDENTIALED_CHECKS_MVP_PLAN.md exists"

check_file "$INSTALL_DIR/public/index.php" "public/index.php exists"
check_file "$INSTALL_DIR/public/css/app.css" "public/css/app.css exists"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/public/index.php" "www-data readable: public/index.php"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/health.php" "www-data readable: api/health.php"

check_file "$INSTALL_DIR/api/lib_reconciliation.php" "api/lib_reconciliation.php exists"
check_file "$INSTALL_DIR/api/lib_worker_jobs.php" "api/lib_worker_jobs.php exists"
check_file "$INSTALL_DIR/api/lib_credentialed_checks.php" "api/lib_credentialed_checks.php exists"
check_file "$INSTALL_DIR/api/credentialed_checks.php" "api/credentialed_checks.php exists"
check_file "$INSTALL_DIR/api/lib_secrets.php" "api/lib_secrets.php exists"
check_file "$INSTALL_DIR/api/lib_credential_profiles.php" "api/lib_credential_profiles.php exists"
check_file "$INSTALL_DIR/api/lib_credential_check_ops.php" "api/lib_credential_check_ops.php exists"
check_file "$INSTALL_DIR/api/credential_profiles.php" "api/credential_profiles.php exists"
check_file "$INSTALL_DIR/api/credential_check_jobs.php" "api/credential_check_jobs.php exists"
check_file "$INSTALL_DIR/api/credential_check_runs.php" "api/credential_check_runs.php exists"
check_file "$INSTALL_DIR/api/lib_credential_profile_transport_test.php" "api/lib_credential_profile_transport_test.php exists"
check_file "$INSTALL_DIR/daemon/cred_transport_cli.py" "daemon/cred_transport_cli.py exists"
check_file "$INSTALL_DIR/daemon/cred_transport_ssh.py" "daemon/cred_transport_ssh.py exists"
check_file "$INSTALL_DIR/daemon/cred_transport_snmp.py" "daemon/cred_transport_snmp.py exists"
check_file "$INSTALL_DIR/api/recon_diagnostics.php" "api/recon_diagnostics.php exists"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/lib_reconciliation.php" "www-data readable: lib_reconciliation.php"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/lib_worker_jobs.php" "www-data readable: lib_worker_jobs.php"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/lib_credentialed_checks.php" "www-data readable: lib_credentialed_checks.php"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/credentialed_checks.php" "www-data readable: credentialed_checks.php"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/lib_secrets.php" "www-data readable: lib_secrets.php"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/lib_credential_profiles.php" "www-data readable: lib_credential_profiles.php"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/lib_credential_check_ops.php" "www-data readable: lib_credential_check_ops.php"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/credential_profiles.php" "www-data readable: credential_profiles.php"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/credential_check_jobs.php" "www-data readable: credential_check_jobs.php"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/credential_check_runs.php" "www-data readable: credential_check_runs.php"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/lib_credential_profile_transport_test.php" "www-data readable: lib_credential_profile_transport_test.php"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/daemon/cred_transport_cli.py" "www-data readable: cred_transport_cli.py"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/daemon/cred_transport_ssh.py" "www-data readable: cred_transport_ssh.py"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/daemon/cred_transport_snmp.py" "www-data readable: cred_transport_snmp.py"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/recon_diagnostics.php" "www-data readable: recon_diagnostics.php"

check_file "$INSTALL_DIR/api/zabbix_sync_worker.php" "api/zabbix_sync_worker.php exists"
check_file "$INSTALL_DIR/api/zabbix_output_worker.php" "api/zabbix_output_worker.php exists"
check_readable_as_user "$APP_USER" "$INSTALL_DIR/api/zabbix_sync_worker.php" "surveytrace readable: zabbix_sync_worker.php"
check_readable_as_user "$APP_USER" "$INSTALL_DIR/api/zabbix_output_worker.php" "surveytrace readable: zabbix_output_worker.php"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/zabbix_sync_worker.php" "www-data readable: zabbix_sync_worker.php"
check_readable_as_user "$WEB_GROUP" "$INSTALL_DIR/api/zabbix_output_worker.php" "www-data readable: zabbix_output_worker.php"

check_file "$INSTALL_DIR/daemon/scanner_daemon.py" "scanner_daemon.py exists"
check_file "$INSTALL_DIR/daemon/recon_observations.py" "recon_observations.py exists"
check_file "$INSTALL_DIR/daemon/worker_jobs.py" "worker_jobs.py exists"
check_file "$INSTALL_DIR/daemon/scheduler_daemon.py" "scheduler_daemon.py exists"
check_file "$INSTALL_DIR/daemon/collector_ingest_worker.py" "collector_ingest_worker.py exists"
check_file "$INSTALL_DIR/daemon/collector_ingest_mirror.py" "collector_ingest_mirror.py exists"
check_file "$INSTALL_DIR/daemon/credential_check_worker.py" "credential_check_worker.py exists"
check_file "$INSTALL_DIR/daemon/cred_check_run.py" "cred_check_run.py exists"
check_file "$INSTALL_DIR/daemon/cred_check_ssh_os_release.py" "cred_check_ssh_os_release.py exists"
check_file "$INSTALL_DIR/daemon/cred_check_ssh_packages.py" "cred_check_ssh_packages.py exists"
check_file "$INSTALL_DIR/daemon/cred_check_snmp_identity.py" "cred_check_snmp_identity.py exists"
check_file "$INSTALL_DIR/daemon/cred_secret_decrypt.py" "cred_secret_decrypt.py exists"
check_file "$INSTALL_DIR/daemon/cred_check_os_release_selftest.py" "cred_check_os_release_selftest.py exists"
check_file "$INSTALL_DIR/daemon/cred_check_package_inventory_selftest.py" "cred_check_package_inventory_selftest.py exists"
check_file "$INSTALL_DIR/daemon/cred_check_snmp_identity_selftest.py" "cred_check_snmp_identity_selftest.py exists"
check_file "$INSTALL_DIR/daemon/st_software_observation_selftest.py" "st_software_observation_selftest.py exists"
check_dir "$INSTALL_DIR/scripts" "scripts/ directory exists"
while IFS= read -r _st_manifest_script; do
    [[ -z "$_st_manifest_script" ]] && continue
    check_file "$INSTALL_DIR/scripts/$_st_manifest_script" "scripts/$_st_manifest_script exists"
done < <(php "$INSTALL_DIR/scripts/deploy_manifest_export.php" scripts_php)
check_file "$INSTALL_DIR/daemon/cred_decrypt_cli.php" "cred_decrypt_cli.php exists"
check_executable_as_user "$APP_USER" "$VENV_DIR/bin/python3" "surveytrace executable: venv python3"

check_file "$DB_FILE" "surveytrace.db exists"
check_mode "$DB_FILE" "660" "surveytrace.db mode"
check_readable_as_user "$APP_USER" "$DB_FILE" "surveytrace readable: surveytrace.db"
if runuser -u "$APP_USER" -- test -w "$DB_FILE" >/dev/null 2>&1; then
    check_ok "surveytrace writable: surveytrace.db"
else
    check_fail "surveytrace writable: surveytrace.db"
fi

check_systemd_unit_present "surveytrace-daemon.service"
check_systemd_unit_present "surveytrace-scheduler.service"
check_systemd_unit_present "surveytrace-collector-ingest.service"
check_systemd_unit_present "surveytrace-credential-check-worker.service"
check_systemd_unit_enabled "surveytrace-daemon.service"
check_systemd_unit_enabled "surveytrace-scheduler.service"
check_systemd_unit_enabled "surveytrace-collector-ingest.service"
check_systemd_unit_enabled "surveytrace-credential-check-worker.service"
check_systemd_unit_rw_policy "surveytrace-daemon.service"
check_systemd_unit_rw_policy "surveytrace-scheduler.service"
check_systemd_unit_rw_policy "surveytrace-collector-ingest.service"
check_systemd_unit_rw_policy "surveytrace-credential-check-worker.service"
check_systemd_unit_has_line "surveytrace-collector-ingest.service" '^EnvironmentFile=-/etc/surveytrace/surveytrace\.env$' "collector-ingest unit has EnvironmentFile"
check_systemd_unit_has_line "surveytrace-collector-ingest.service" '^User=surveytrace$' "collector-ingest unit has User=surveytrace"
check_systemd_unit_has_line "surveytrace-collector-ingest.service" '^Group=surveytrace$' "collector-ingest unit has Group=surveytrace"
check_systemd_unit_has_line "surveytrace-collector-ingest.service" '^SupplementaryGroups=www-data$' "collector-ingest unit has SupplementaryGroups=www-data"
check_systemd_unit_has_line "surveytrace-collector-ingest.service" '^WorkingDirectory=/opt/surveytrace/daemon$' "collector-ingest unit has WorkingDirectory"
check_systemd_unit_has_line "surveytrace-collector-ingest.service" '^Restart=on-failure$' "collector-ingest unit has Restart=on-failure"
SUDO_HELPER_DROPIN="/etc/sudoers.d/surveytrace-credential-secret-helper"
ENV_FILE="/etc/surveytrace/surveytrace.env"
PHP_BIN_REAL="$(st_detect_php_cli_bin || true)"
if [[ -n "$PHP_BIN_REAL" ]]; then
    st_upsert_env_kv "$ENV_FILE" "SURVEYTRACE_PHP_CLI_BIN" "$PHP_BIN_REAL"
    install -m 440 /dev/null "$SUDO_HELPER_DROPIN"
    cat > "$SUDO_HELPER_DROPIN" <<EOF
# SurveyTrace credential secret helper (least-privilege).
www-data ALL=(surveytrace) NOPASSWD: ${PHP_BIN_REAL} ${INSTALL_DIR}/daemon/cred_secret_ops_cli.php

EOF
    if visudo -cf "$SUDO_HELPER_DROPIN" >/dev/null 2>&1; then
        check_ok "sudoers helper drop-in valid: $SUDO_HELPER_DROPIN"
    else
        check_fail "sudoers helper drop-in invalid: $SUDO_HELPER_DROPIN"
    fi
else
    check_fail "no CLI-capable php binary found for sudoers helper rule"
fi
if [[ -f "$ENV_FILE" ]]; then
    check_ok "env file present: $ENV_FILE"
else
    check_warn "env file missing: $ENV_FILE (set SURVEYTRACE_CRED_SECRET_KEY)"
fi
if runuser -u "$WEB_GROUP" -- test -r "$ENV_FILE" >/dev/null 2>&1; then
    check_fail "www-data can read $ENV_FILE (must not be readable by www-data)"
else
    check_ok "www-data cannot read $ENV_FILE"
fi
if runuser -u "$APP_USER" -- test -r "$ENV_FILE" >/dev/null 2>&1; then
    check_ok "surveytrace can read $ENV_FILE"
else
    check_fail "surveytrace can read $ENV_FILE"
fi
_st_helper_status="$(sudo -u "$WEB_GROUP" sudo -n -u "$APP_USER" -- "$PHP_BIN_REAL" "$INSTALL_DIR/daemon/cred_secret_ops_cli.php" <<< '{"action":"status"}' 2>/dev/null || true)"
_st_key_is_configured=0
if [[ -f "$ENV_FILE" ]] && grep -Eq '^SURVEYTRACE_CRED_SECRET_KEY=' "$ENV_FILE"; then
    _st_key_is_configured=1
fi
if [[ -n "$_st_helper_status" ]] && ST_EXPECT_KEY="$_st_key_is_configured" php -r '$j=json_decode(stream_get_contents(STDIN),true); $ok=is_array($j)&&!empty($j["ok"])&&!empty($j["status"]["available"])&&!empty($j["status"]["env_file_present"])&&!empty($j["status"]["env_file_readable"]); $need=(getenv("ST_EXPECT_KEY")==="1"); if($need){$ok=$ok&&!empty($j["status"]["key_loaded"]);} exit($ok?0:1);' <<<"$_st_helper_status" >/dev/null 2>&1; then
    if [[ "$_st_key_is_configured" -eq 1 ]]; then
        check_ok "www-data helper sudo path can load credential key"
    else
        check_ok "www-data helper sudo path reachable (no credential key configured)"
    fi
else
    if [[ "$_st_key_is_configured" -eq 1 ]]; then
        check_fail "www-data helper sudo path cannot load credential key (check sudoers/env file)"
    else
        check_fail "www-data helper sudo path unavailable (check sudoers/php path)"
    fi
fi
if runuser -u "$APP_USER" -- "$VENV_DIR/bin/python3" "$INSTALL_DIR/daemon/collector_ingest_worker.py" --check-db-open >/dev/null 2>&1; then
    check_ok "collector ingest runtime DB-open check"
else
    check_fail "collector ingest runtime DB-open check"
fi

if command -v zabbix_sender >/dev/null 2>&1; then
    check_ok "zabbix_sender available"
else
    check_warn "zabbix_sender not found; install zabbix-sender on Debian/Ubuntu to use SurveyTrace -> Zabbix output."
fi

if command -v php >/dev/null 2>&1; then
    while IFS= read -r _st_php; do
        [[ -z "$_st_php" ]] && continue
        php -l "$INSTALL_DIR/api/$_st_php" >/dev/null 2>&1 && check_ok "php -l api/$_st_php" || check_fail "php -l api/$_st_php"
    done < <(php "$INSTALL_DIR/scripts/deploy_manifest_export.php" api_files)
    php -l "$INSTALL_DIR/daemon/cred_decrypt_cli.php" >/dev/null 2>&1 && check_ok "php -l daemon/cred_decrypt_cli.php" || check_fail "php -l daemon/cred_decrypt_cli.php"
    while IFS= read -r _st_scr; do
        [[ -z "$_st_scr" ]] && continue
        php -l "$INSTALL_DIR/scripts/$_st_scr" >/dev/null 2>&1 && check_ok "php -l scripts/$_st_scr" || check_fail "php -l scripts/$_st_scr"
    done < <(php "$INSTALL_DIR/scripts/deploy_manifest_export.php" scripts_php)
else
    check_warn "php not in PATH — skipped php -l (API / scripts manifest)"
fi
if command -v python3 >/dev/null 2>&1; then
    for _manifest_py_key in daemon_core_py daemon_optional_py daemon_other_files; do
        while IFS= read -r _st_py; do
            [[ -z "$_st_py" ]] && continue
            [[ "$_st_py" == *.py ]] || continue
            python3 -m py_compile "$INSTALL_DIR/daemon/$_st_py" >/dev/null 2>&1 && \
                check_ok "python3 -m py_compile daemon/$_st_py" || \
                check_fail "python3 -m py_compile daemon/$_st_py"
        done < <(php "$INSTALL_DIR/scripts/deploy_manifest_export.php" "$_manifest_py_key")
    done
else
    check_warn "python3 not in PATH — skipped py_compile daemon/*.py"
fi

if [[ "$CHECK_FAIL" -gt 0 ]]; then
    die "Post-install validation failed with $CHECK_FAIL critical issue(s) and $CHECK_WARN warning(s)."
fi
ok "Post-install validation complete ($CHECK_WARN warning(s))"

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
echo -e "${GRN}║${NC}  Col.ingest:  systemctl status surveytrace-collector-ingest  "
echo -e "${GRN}║${NC}  Cred checks: systemctl status surveytrace-credential-check-worker  "
echo -e "${GRN}║${NC}  Firewall:    ufw status numbered                     "
echo -e "${GRN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Daemon status:  systemctl status surveytrace-daemon"
echo "  Daemon logs:    journalctl -u surveytrace-daemon -f"
echo "  NVD sync:       sudo -u $APP_USER $VENV_DIR/bin/python3 $INSTALL_DIR/daemon/sync_nvd.py"
echo "  Firewall:       ufw status numbered"
echo "  Add LAN rule:   ufw allow from 192.168.x.0/24 to any port 80 proto tcp"
echo ""
