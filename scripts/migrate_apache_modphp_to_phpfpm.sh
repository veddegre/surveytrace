#!/usr/bin/env bash
# SurveyTrace — migrate Apache from libapache2-mod-php (mod_php / mpm_prefork) to php-fpm + mod_proxy_fcgi.
#
# Target: Debian/Ubuntu with apache2. Keep in sync with setup.sh (STEP 8 — Apache + php-fpm).
#
# Usage (as root):
#   sudo SURVEYTRACE_INSTALL_DIR=/opt/surveytrace bash /opt/surveytrace/scripts/migrate_apache_modphp_to_phpfpm.sh
#   sudo bash scripts/migrate_apache_modphp_to_phpfpm.sh --dry-run
#
# Environment:
#   SURVEYTRACE_INSTALL_DIR   Install root (default: /opt/surveytrace)
#   SURVEYTRACE_PHP_BIN       CLI used to read PHP_MAJOR.MINOR (default: /usr/bin/php)
#   SURVEYTRACE_APACHE_SITE   sites-available basename without .conf (default: surveytrace)
#
# After success: restart workers once so migrations/bootstrap reload (see CHANGELOG / deployment.md).

set -euo pipefail

DRY_RUN=0
for a in "$@"; do
  case "$a" in
    --dry-run|-n) DRY_RUN=1 ;;
    -h|--help)
      sed -n '1,25p' "$0" | sed -e 's/^# \{0,1\}//'
      exit 0
      ;;
  esac
done

die() { echo "migrate_apache_modphp_to_phpfpm: $*" >&2; exit 1; }
info() { echo "[info] $*"; }
warn() { echo "[warn] $*" >&2; }

[[ "${EUID:-0}" -eq 0 ]] || die "run as root (sudo bash $0)"

[[ -d /etc/apache2 ]] && command -v apache2ctl >/dev/null 2>&1 || \
  die "apache2 not found — this script only supports Debian/Ubuntu apache2"

INSTALL_DIR="${SURVEYTRACE_INSTALL_DIR:-/opt/surveytrace}"
INSTALL_DIR="${INSTALL_DIR%/}"
WEBROOT="${INSTALL_DIR}/public"
PHP_BIN="${SURVEYTRACE_PHP_BIN:-/usr/bin/php}"
APACHE_SITE="${SURVEYTRACE_APACHE_SITE:-surveytrace}"
APACHE_CONF="/etc/apache2/sites-available/${APACHE_SITE}.conf"

[[ -d "$WEBROOT" ]] || die "DocumentRoot missing: $WEBROOT (set SURVEYTRACE_INSTALL_DIR)"
[[ -d "${INSTALL_DIR}/api" ]] || die "api dir missing: ${INSTALL_DIR}/api"

PHP_VER="$("$PHP_BIN" -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || true)"
[[ -n "$PHP_VER" && "$PHP_VER" != "0.0" ]] || die "could not read PHP version from $PHP_BIN"

FPM_SOCK="/run/php/php${PHP_VER}-fpm.sock"
FPM_UNIT="php${PHP_VER}-fpm.service"
PHP_ETC_BASE="/etc/php/${PHP_VER}/fpm"
FPM_POOL_D="${PHP_ETC_BASE}/pool.d"

MOD_PROXY_FCGI_SO="/usr/lib/apache2/modules/mod_proxy_fcgi.so"

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

apt_install() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] apt-get install -y $*"
    return 0
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

install_mod_proxy_fcgi() {
  if [[ -f "$MOD_PROXY_FCGI_SO" ]]; then
    return 0
  fi
  if apt_install libapache2-mod-proxy-fcgi; then
    return 0
  fi
  info "refreshing apt index and retrying libapache2-mod-proxy-fcgi…"
  apt-get update -qq
  apt_install libapache2-mod-proxy-fcgi
}

BKDIR="/root/surveytrace-migrate-fpm-$(date +%Y%m%d%H%M%S)"
if [[ "$DRY_RUN" -eq 0 ]]; then
  mkdir -p "$BKDIR"
  cp -aL /etc/apache2/sites-enabled "$BKDIR/sites-enabled" 2>/dev/null || true
  cp -aL /etc/apache2/mods-enabled "$BKDIR/mods-enabled" 2>/dev/null || true
  [[ -f "$APACHE_CONF" ]] && cp -a "$APACHE_CONF" "$BKDIR/${APACHE_SITE}.conf.bak" || true
  info "backup written under $BKDIR"
else
  info "dry-run: would backup apache mods/sites to $BKDIR"
fi

info "PHP version: $PHP_VER (from $PHP_BIN); FPM socket: $FPM_SOCK"

if [[ "$DRY_RUN" -eq 0 ]]; then
  apt-get update -qq
fi

# Versioned FPM + extensions commonly required by SurveyTrace (safe if already installed).
if apt-cache show "php${PHP_VER}-fpm" &>/dev/null; then
  apt_install "php${PHP_VER}-fpm" "php${PHP_VER}-cli" "php${PHP_VER}-sqlite3" "php${PHP_VER}-mbstring" "php${PHP_VER}-curl" || \
    warn "some php${PHP_VER}-* packages failed to install — fix apt and re-run"
else
  die "apt has no package php${PHP_VER}-fpm — install matching php-fpm for $PHP_BIN"
fi

install_mod_proxy_fcgi || [[ -f "$MOD_PROXY_FCGI_SO" ]] || die "mod_proxy_fcgi missing (libapache2-mod-proxy-fcgi)"

# Disable all libapache2-mod-php* modules (they require mpm_prefork and conflict with mpm_event + fcgi).
shopt -s nullglob
for f in /etc/apache2/mods-enabled/php*.load; do
  mod=$(basename "$f" .load)
  info "disabling Apache module: $mod"
  run a2dismod -f "$mod" 2>/dev/null || true
done
shopt -u nullglob

# Switch to event MPM (required for sane concurrency with php-fpm).
if [[ "$DRY_RUN" -eq 0 ]]; then
  if a2query -q -m mpm_event 2>/dev/null; then
    info "mpm_event already enabled"
  else
    if a2query -q -m mpm_prefork 2>/dev/null; then
      a2dismod mpm_prefork || die "a2dismod mpm_prefork failed"
    fi
    if a2query -q -m mpm_worker 2>/dev/null; then
      a2dismod mpm_worker || die "a2dismod mpm_worker failed"
    fi
    a2enmod mpm_event || die "a2enmod mpm_event failed"
  fi
else
  info "dry-run: would ensure mpm_event (disable prefork/worker if needed)"
fi

run a2enmod proxy proxy_fcgi setenvif rewrite 2>/dev/null || true

if [[ -d "$FPM_POOL_D" ]]; then
  pool_dropin="${FPM_POOL_D}/zzz-surveytrace-install-dir.conf"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] would write $pool_dropin with env[SURVEYTRACE_INSTALL_DIR]=$INSTALL_DIR"
  else
    install -m 0644 /dev/null "$pool_dropin"
    cat > "$pool_dropin" <<POOL
; Written by migrate_apache_modphp_to_phpfpm.sh — merged into the default [www] pool.
[www]
env[SURVEYTRACE_INSTALL_DIR] = ${INSTALL_DIR}
POOL
    info "wrote $pool_dropin"
  fi
else
  warn "php-fpm pool.d not found at $FPM_POOL_D — skipping env drop-in (non-Debian layout?)"
fi

info "writing Apache vhost: $APACHE_CONF"

write_vhost() {
  cat <<VHOST
<VirtualHost *:80>
    DocumentRoot ${WEBROOT}
    DirectoryIndex index.php

    Alias /api ${INSTALL_DIR}/api
    <Directory ${INSTALL_DIR}/api>
        Options -Indexes
        AllowOverride None
        Require all granted
        CGIPassAuth On
        <FilesMatch "\\.php\$">
            SetHandler "proxy:unix:${FPM_SOCK}|fcgi://localhost"
        </FilesMatch>
    </Directory>

    <Directory ${WEBROOT}>
        Options -Indexes
        AllowOverride All
        Require all granted
        CGIPassAuth On
        <FilesMatch "\\.php\$">
            SetHandler "proxy:unix:${FPM_SOCK}|fcgi://localhost"
        </FilesMatch>
    </Directory>

    <DirectoryMatch "^${INSTALL_DIR}/(data|sql|daemon|venv)">
        Require all denied
    </DirectoryMatch>

    ErrorLog  \${APACHE_LOG_DIR}/${APACHE_SITE}_error.log
    CustomLog \${APACHE_LOG_DIR}/${APACHE_SITE}_access.log combined
</VirtualHost>
VHOST
}

if [[ "$DRY_RUN" -eq 1 ]]; then
  write_vhost | sed 's/^/[dry-run vhost] /'
else
  write_vhost > "$APACHE_CONF"
fi

run a2ensite "$APACHE_SITE"
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[dry-run] a2dissite 000-default 2>/dev/null || true"
else
  a2dissite 000-default 2>/dev/null || true
fi

if [[ "$DRY_RUN" -eq 0 ]]; then
  apache2ctl configtest || die "apache2ctl configtest failed — restore from $BKDIR if needed"
  systemctl enable "$FPM_UNIT" 2>/dev/null || true
  systemctl restart "$FPM_UNIT"
  [[ -S "$FPM_SOCK" ]] || warn "socket not yet present: $FPM_SOCK (check systemctl status $FPM_UNIT)"
  systemctl restart apache2
else
  info "dry-run: skipped apache2ctl configtest / systemctl restart"
fi

info "done."
info "Verify: curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1/ && curl -sS http://127.0.0.1/api/health.php | head -c 200"
info "Credential helper: pool user must match sudoers (often www-data). Run: sudo -l -U www-data"
info "If encryption still fails, re-run setup.sh/deploy.sh sudoers post-migrate (php-fpm user from pool.d/www.conf)."
