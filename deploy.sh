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
sudo cp "$SRC"/api/schedules.php       "$DEST/api/"
sudo cp "$SRC"/api/enrichment.php      "$DEST/api/"
sudo cp "$SRC"/api/dashboard.php       "$DEST/api/"
sudo cp "$SRC"/api/export.php          "$DEST/api/"
echo "  API files deployed"

# ---------------------------------------------------------------------------
# Public (web UI)
# ---------------------------------------------------------------------------
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
sudo cp "$SRC"/daemon/sources/stubs.py     "$DEST/daemon/sources/" 2>/dev/null || true

# sync_nvd.py only if it exists (large script, less frequently changed)
[ -f "$SRC/daemon/sync_nvd.py" ] && sudo cp "$SRC/daemon/sync_nvd.py" "$DEST/daemon/"

echo "  Daemon files deployed"

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

echo ""
echo "Deploy complete."
