#!/usr/bin/env bash
# Deploy updated collector runtime files to an existing collector node.
set -euo pipefail

DEST="/opt/surveytrace"
SRC="$(cd "$(dirname "$0")/.." && pwd)"

echo "Deploying SurveyTrace collector files..."
sudo mkdir -p "$DEST/daemon" "$DEST/sql" "$DEST/daemon/sources"

for f in scanner_daemon.py fingerprint.py profiles.py ai_cloud_client.py collector_agent.py collector_parity_runner.py; do
  sudo cp "$SRC/daemon/$f" "$DEST/daemon/"
done
sudo cp "$SRC/sql/schema.sql" "$DEST/sql/"
for f in "$SRC"/daemon/sources/*.py; do
  [ -f "$f" ] && sudo cp "$f" "$DEST/daemon/sources/"
done

sudo chown -R surveytrace:surveytrace "$DEST/daemon" "$DEST/sql" 2>/dev/null || true
sudo systemctl restart surveytrace-collector
sudo systemctl is-active --quiet surveytrace-collector && echo "collector: running" || echo "collector: FAILED"
