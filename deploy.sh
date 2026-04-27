#!/bin/bash
# SurveyTrace deploy script
# Copies source files from the repo to /opt/surveytrace and restarts daemons.
# Run from ~/surveytrace-repo after pulling changes:
#   bash deploy.sh
set -e

DEST="/opt/surveytrace"
SRC="$(cd "$(dirname "$0")" && pwd)"

echo "Deploying SurveyTrace from $SRC to $DEST..."

# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
sudo cp "$SRC"/api/db.php              "$DEST/api/"
sudo cp "$SRC"/api/assets.php          "$DEST/api/"
sudo cp "$SRC"/api/findings.php        "$DEST/api/"
sudo cp "$SRC"/api/findings_export.php "$DEST/api/"
sudo cp "$SRC"/api/scan_start.php      "$DEST/api/"
sudo cp "$SRC"/api/scan_status.php     "$DEST/api/"
sudo cp "$SRC"/api/scan_abort.php      "$DEST/api/"
sudo cp "$SRC"/api/auth.php            "$DEST/api/"
sudo cp "$SRC"/api/schedules.php       "$DEST/api/"
sudo cp "$SRC"/api/enrichment.php      "$DEST/api/"
sudo cp "$SRC"/api/dashboard.php       "$DEST/api/"
sudo cp "$SRC"/api/feeds.php           "$DEST/api/"
sudo cp "$SRC"/api/feed_sync_lib.php   "$DEST/api/"
sudo cp "$SRC"/api/scan_history.php    "$DEST/api/"
sudo cp "$SRC"/api/logout.php          "$DEST/api/"
sudo cp "$SRC"/api/settings.php        "$DEST/api/"
sudo cp "$SRC"/api/export.php          "$DEST/api/"
echo "  API files deployed"

# ---------------------------------------------------------------------------
# Public (web UI)
# ---------------------------------------------------------------------------
sudo mkdir -p "$DEST/public/css"
sudo cp "$SRC"/public/css/app.css      "$DEST/public/css/"
sudo cp "$SRC"/public/index.php        "$DEST/public/"
echo "  Web UI deployed"

# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------
sudo cp "$SRC"/daemon/scanner_daemon.py    "$DEST/daemon/"
sudo cp "$SRC"/daemon/scheduler_daemon.py  "$DEST/daemon/"
sudo cp "$SRC"/daemon/fingerprint.py       "$DEST/daemon/"
sudo cp "$SRC"/daemon/profiles.py          "$DEST/daemon/"

# Enrichment sources
sudo cp "$SRC"/daemon/sources/__init__.py  "$DEST/daemon/sources/" 2>/dev/null || true
sudo cp "$SRC"/daemon/sources/unifi.py     "$DEST/daemon/sources/" 2>/dev/null || true
sudo cp "$SRC"/daemon/sources/snmp.py      "$DEST/daemon/sources/" 2>/dev/null || true
sudo cp "$SRC"/daemon/sources/dhcp.py      "$DEST/daemon/sources/" 2>/dev/null || true
sudo cp "$SRC"/daemon/sources/dns_logs.py  "$DEST/daemon/sources/" 2>/dev/null || true
sudo cp "$SRC"/daemon/sources/firewall_logs.py "$DEST/daemon/sources/" 2>/dev/null || true
sudo cp "$SRC"/daemon/sources/stubs.py     "$DEST/daemon/sources/" 2>/dev/null || true

# Feed sync from the UI: PHP-FPM runs sync in-process; Apache/mod_php spawns this worker.
sudo cp "$SRC"/daemon/feed_sync_worker.php "$DEST/daemon/"

# sync_nvd.py only if it exists (large script, less frequently changed)
[ -f "$SRC/daemon/sync_nvd.py" ] && sudo cp "$SRC/daemon/sync_nvd.py" "$DEST/daemon/"
[ -f "$SRC/daemon/sync_oui.py" ] && sudo cp "$SRC/daemon/sync_oui.py" "$DEST/daemon/"
[ -f "$SRC/daemon/sync_webfp.py" ] && sudo cp "$SRC/daemon/sync_webfp.py" "$DEST/daemon/"

echo "  Daemon files deployed"

# ---------------------------------------------------------------------------
# Permission sanity for UI-triggered feed sync + daemon runtime
# ---------------------------------------------------------------------------
if id surveytrace >/dev/null 2>&1; then
  sudo usermod -aG surveytrace www-data 2>/dev/null || true
  # venv must be writable by app user for pip installs/upgrades
  sudo chown -R surveytrace:surveytrace "$DEST/venv" 2>/dev/null || true
  # Parent dirs must be traversable for web-triggered script execution
  sudo chmod 755 "$DEST" 2>/dev/null || true
  sudo chmod 755 "$DEST/venv" "$DEST/venv/bin" 2>/dev/null || true
  sudo chmod 755 "$DEST/venv/bin/python3" 2>/dev/null || true
  # daemon scripts: surveytrace-owned, group-readable/traversable by group members
  sudo chown -R surveytrace:surveytrace "$DEST/daemon" 2>/dev/null || true
  sudo find "$DEST/daemon" -type d -exec chmod 750 {} \; 2>/dev/null || true
  sudo find "$DEST/daemon" -type f -exec chmod 640 {} \; 2>/dev/null || true
  # data dir: writable by daemon + web group; setgid keeps group on new files
  sudo chown -R surveytrace:www-data "$DEST/data" 2>/dev/null || true
  sudo find "$DEST/data" -type d -exec chmod 2770 {} \; 2>/dev/null || true
  sudo find "$DEST/data" -type f -exec chmod 660 {} \; 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# SQL schema (reference only — don't re-apply to existing DB)
# ---------------------------------------------------------------------------
sudo cp "$SRC"/sql/schema.sql          "$DEST/sql/"
echo "  Schema file updated"

# ---------------------------------------------------------------------------
# Restart daemons
# ---------------------------------------------------------------------------
echo "Restarting daemons..."
sudo systemctl restart surveytrace-daemon
sudo systemctl restart surveytrace-scheduler

# Brief pause then check status
sleep 2
if sudo systemctl is-active --quiet surveytrace-daemon; then
    echo "  surveytrace-daemon: running"
else
    echo "  surveytrace-daemon: FAILED — check: sudo journalctl -u surveytrace-daemon -n 20"
fi

if sudo systemctl is-active --quiet surveytrace-scheduler; then
    echo "  surveytrace-scheduler: running"
else
    echo "  surveytrace-scheduler: FAILED — check: sudo journalctl -u surveytrace-scheduler -n 20"
fi

# ---------------------------------------------------------------------------
# Post-deploy verification
# ---------------------------------------------------------------------------
echo "Running post-deploy checks..."
VERIFY_OK=1

check_file() {
  local p="$1"
  local label="$2"
  if [ "$(id -u)" -eq 0 ]; then
    if [ -f "$p" ]; then
      echo "  [OK] $label: $p"
    else
      echo "  [FAIL] $label missing: $p"
      VERIFY_OK=0
    fi
  else
    if sudo test -f "$p" >/dev/null 2>&1; then
      echo "  [OK] $label: $p"
    else
      echo "  [FAIL] $label missing: $p"
      VERIFY_OK=0
    fi
  fi
}

check_cmd() {
  local cmd="$1"
  local label="$2"
  if eval "$cmd" >/dev/null 2>&1; then
    echo "  [OK] $label"
  else
    echo "  [FAIL] $label"
    VERIFY_OK=0
  fi
}

check_as_user() {
  local user="$1"
  local test_expr="$2"
  local label="$3"
  if [ "$(id -u)" -eq 0 ]; then
    if runuser -u "$user" -- sh -lc "$test_expr" >/dev/null 2>&1; then
      echo "  [OK] $label"
    else
      echo "  [FAIL] $label"
      VERIFY_OK=0
    fi
  else
    if sudo -u "$user" sh -lc "$test_expr" >/dev/null 2>&1; then
      echo "  [OK] $label"
    else
      echo "  [FAIL] $label"
      VERIFY_OK=0
    fi
  fi
}

check_file "$DEST/api/feeds.php" "feeds API"
check_file "$DEST/api/feed_sync_lib.php" "feed_sync_lib (required by feeds.php)"
check_file "$DEST/api/scan_history.php" "scan history API"
check_file "$DEST/daemon/feed_sync_worker.php" "feed sync CLI worker (required for non-FPM PHP)"
check_file "$DEST/daemon/sync_nvd.py" "NVD sync script"
check_file "$DEST/daemon/sync_oui.py" "OUI sync script"
check_file "$DEST/daemon/sync_webfp.py" "WebFP sync script"
check_file "$DEST/data/surveytrace.db" "main DB"
check_file "/etc/cron.d/surveytrace-fp" "fingerprint cron"

# Effective access checks for web-triggered feed sync path
check_as_user "www-data" "test -r \"$DEST/daemon/feed_sync_worker.php\"" \
  "www-data can read feed_sync_worker.php"
check_as_user "www-data" "test -r \"$DEST/daemon/sync_nvd.py\"" \
  "www-data can read sync_nvd.py"
check_as_user "www-data" "test -r \"$DEST/daemon/sync_oui.py\"" \
  "www-data can read sync_oui.py"
check_as_user "www-data" "test -r \"$DEST/daemon/sync_webfp.py\"" \
  "www-data can read sync_webfp.py"
check_as_user "www-data" "test -w \"$DEST/data\"" \
  "www-data can write data dir"
check_as_user "surveytrace" "test -w \"$DEST/data\"" \
  "surveytrace can write data dir"

if [ "$VERIFY_OK" -eq 1 ]; then
  echo "  Post-deploy checks: PASS"
else
  echo "  Post-deploy checks: FAIL (see lines above)"
fi

echo ""
echo "Deploy complete."
