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
API_FILES=(
  db.php
  assets.php
  findings.php
  findings_export.php
  scan_start.php
  scan_status.php
  scan_abort.php
  scan_delete.php
  auth.php
  auth_oidc.php
  auth_qr.php
  schedules.php
  enrichment.php
  dashboard.php
  feeds.php
  feed_sync_lib.php
  scan_history.php
  logout.php
  settings.php
  health.php
  export.php
  devices.php
)
for f in "${API_FILES[@]}"; do
  sudo cp "$SRC/api/$f" "$DEST/api/"
done
echo "  API files deployed"

# ---------------------------------------------------------------------------
# Public (web UI)
# ---------------------------------------------------------------------------
sudo mkdir -p "$DEST/public/css"
sudo cp "$SRC/public/css/app.css" "$DEST/public/css/"
sudo cp "$SRC/public/index.php" "$DEST/public/"
echo "  Web UI deployed"

# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------
DAEMON_CORE=(
  scanner_daemon.py
  scheduler_daemon.py
  fingerprint.py
  profiles.py
)
for f in "${DAEMON_CORE[@]}"; do
  sudo cp "$SRC/daemon/$f" "$DEST/daemon/"
done

SOURCE_FILES=(
  __init__.py
  unifi.py
  snmp.py
  dhcp.py
  dns_logs.py
  firewall_logs.py
  stubs.py
)
for f in "${SOURCE_FILES[@]}"; do
  sudo cp "$SRC/daemon/sources/$f" "$DEST/daemon/sources/" 2>/dev/null || true
done

sudo cp "$SRC/daemon/feed_sync_worker.php" "$DEST/daemon/"
sudo cp "$SRC/daemon/feed_sync_cancel.py" "$DEST/daemon/"
sudo cp "$SRC/daemon/backup_db.sh" "$DEST/daemon/"
sudo cp "$SRC/daemon/restore_db.sh" "$DEST/daemon/"

[ -f "$SRC/daemon/sync_nvd.py" ] && sudo cp "$SRC/daemon/sync_nvd.py" "$DEST/daemon/"
[ -f "$SRC/daemon/sync_oui.py" ] && sudo cp "$SRC/daemon/sync_oui.py" "$DEST/daemon/"
[ -f "$SRC/daemon/sync_webfp.py" ] && sudo cp "$SRC/daemon/sync_webfp.py" "$DEST/daemon/"

echo "  Daemon files deployed"

# ---------------------------------------------------------------------------
# Permission sanity for UI-triggered feed sync + daemon runtime
# ---------------------------------------------------------------------------
if id surveytrace >/dev/null 2>&1; then
  sudo usermod -aG surveytrace www-data 2>/dev/null || true
  sudo chown -R surveytrace:surveytrace "$DEST/venv" 2>/dev/null || true
  sudo chmod 755 "$DEST" 2>/dev/null || true
  sudo chmod 755 "$DEST/venv" "$DEST/venv/bin" 2>/dev/null || true
  sudo chmod 755 "$DEST/venv/bin/python3" 2>/dev/null || true
  sudo chown -R surveytrace:surveytrace "$DEST/daemon" 2>/dev/null || true
  sudo find "$DEST/daemon" -type d -exec chmod 750 {} \; 2>/dev/null || true
  sudo find "$DEST/daemon" -type f -exec chmod 640 {} \; 2>/dev/null || true
  sudo chmod 750 "$DEST/daemon/backup_db.sh" 2>/dev/null || true
  sudo chmod 750 "$DEST/daemon/restore_db.sh" 2>/dev/null || true
  sudo chown -R surveytrace:www-data "$DEST/data" 2>/dev/null || true
  sudo find "$DEST/data" -type d -exec chmod 2770 {} \; 2>/dev/null || true
  sudo find "$DEST/data" -type f -exec chmod 660 {} \; 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# SQL schema (reference only — don't re-apply to existing DB)
# ---------------------------------------------------------------------------
sudo cp "$SRC/sql/schema.sql" "$DEST/sql/"
echo "  Schema file updated"

# ---------------------------------------------------------------------------
# Restart daemons
# ---------------------------------------------------------------------------
echo "Restarting daemons..."
sudo systemctl restart surveytrace-daemon
sudo systemctl restart surveytrace-scheduler

sleep 2
if sudo systemctl is-active --quiet surveytrace-daemon; then
  echo "  surveytrace-daemon: running"
else
  echo "  surveytrace-daemon: FAILED"
  echo "      sudo journalctl -u surveytrace-daemon -n 20"
fi

if sudo systemctl is-active --quiet surveytrace-scheduler; then
  echo "  surveytrace-scheduler: running"
else
  echo "  surveytrace-scheduler: FAILED"
  echo "      sudo journalctl -u surveytrace-scheduler -n 20"
fi

# ---------------------------------------------------------------------------
# Post-deploy verification
# ---------------------------------------------------------------------------
echo "Running post-deploy checks..."
VERIFY_OK=1

# Prints [OK]/[FAIL] on first line, path on second (avoids one very long wrapped line).
check_file() {
  local p="$1"
  local label="$2"
  local ok=1
  if [ "$(id -u)" -eq 0 ]; then
    [ -f "$p" ] || ok=0
  else
    sudo test -f "$p" >/dev/null 2>&1 || ok=0
  fi
  if [ "$ok" -eq 1 ]; then
    echo "  [OK] $label"
    echo "       $p"
  else
    echo "  [FAIL] $label (missing)"
    echo "       $p"
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

check_file "$DEST/api/health.php" "health API"
check_file "$DEST/api/feeds.php" "feeds API"
check_file "$DEST/api/feed_sync_lib.php" "feed_sync_lib"
check_file "$DEST/api/scan_history.php" "scan history API"
check_file "$DEST/api/devices.php" "devices API"
check_file "$DEST/daemon/feed_sync_worker.php" "feed_sync_worker (UI sync)"
check_file "$DEST/daemon/feed_sync_cancel.py" "feed_sync_cancel"
check_file "$DEST/daemon/sync_nvd.py" "sync_nvd.py"
check_file "$DEST/daemon/sync_oui.py" "sync_oui.py"
check_file "$DEST/daemon/sync_webfp.py" "sync_webfp.py"
check_file "$DEST/data/surveytrace.db" "surveytrace.db"
check_file "/etc/cron.d/surveytrace-fp" "fingerprint cron"

check_as_user "www-data" "test -r \"$DEST/daemon/feed_sync_worker.php\"" \
  "www-data read: feed_sync_worker.php"
check_as_user "www-data" "test -r \"$DEST/daemon/sync_nvd.py\"" \
  "www-data read: sync_nvd.py"
check_as_user "www-data" "test -r \"$DEST/daemon/sync_oui.py\"" \
  "www-data read: sync_oui.py"
check_as_user "www-data" "test -r \"$DEST/daemon/sync_webfp.py\"" \
  "www-data read: sync_webfp.py"
check_as_user "www-data" "test -w \"$DEST/data\"" \
  "www-data write: data/"
check_as_user "surveytrace" "test -w \"$DEST/data\"" \
  "surveytrace write: data/"

if [ "$VERIFY_OK" -eq 1 ]; then
  echo "  Post-deploy checks: PASS"
else
  echo "  Post-deploy checks: FAIL (see lines above)"
fi

echo ""
echo "Deploy complete."
