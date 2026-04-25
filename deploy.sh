#!/bin/bash
# SurveyTrace deploy script
# Run from ~/surveytrace to push changes to /opt/surveytrace
set -e

DEST="/opt/surveytrace"
SRC="$(cd "$(dirname "$0")" && pwd)"

echo "Deploying SurveyTrace from $SRC to $DEST..."

# API
sudo cp "$SRC"/api/*.php "$DEST/api/"

# Public
sudo cp "$SRC"/public/index.php "$DEST/public/"

# Daemon
sudo cp "$SRC"/daemon/scanner_daemon.py    "$DEST/daemon/"
sudo cp "$SRC"/daemon/scheduler_daemon.py  "$DEST/daemon/"
sudo cp "$SRC"/daemon/fingerprint.py       "$DEST/daemon/"
sudo cp "$SRC"/daemon/profiles.py          "$DEST/daemon/"
sudo cp "$SRC"/daemon/sync_nvd.py          "$DEST/daemon/" 2>/dev/null || true
sudo cp "$SRC"/daemon/sources/*.py         "$DEST/daemon/sources/" 2>/dev/null || true

# SQL schema (don't re-run, just keep in sync)
sudo cp "$SRC"/sql/schema.sql "$DEST/sql/"

echo "Restarting daemons..."
sudo systemctl restart surveytrace-daemon
sudo systemctl restart surveytrace-scheduler

echo "Done. SurveyTrace deployed successfully."
