#!/usr/bin/env bash
# Deploy updated collector runtime files to an existing collector node.
set -euo pipefail

DEST="/opt/surveytrace"
SRC="$(cd "$(dirname "$0")/.." && pwd)"

echo "Deploying SurveyTrace collector files..."
sudo mkdir -p "$DEST/daemon" "$DEST/sql" "$DEST/daemon/sources"

for f in scanner_daemon.py change_detection.py fingerprint.py profiles.py ai_cloud_client.py collector_agent.py collector_parity_runner.py; do
  sudo cp "$SRC/daemon/$f" "$DEST/daemon/"
done
sudo cp "$SRC/sql/schema.sql" "$DEST/sql/"
for f in "$SRC"/daemon/sources/*.py; do
  [ -f "$f" ] && sudo cp "$f" "$DEST/daemon/sources/"
done

sudo chown -R surveytrace:surveytrace "$DEST/daemon" "$DEST/sql" 2>/dev/null || true
if [[ -f /etc/surveytrace/collector.json ]]; then
  sudo chown root:surveytrace /etc/surveytrace/collector.json 2>/dev/null || true
  sudo chmod 660 /etc/surveytrace/collector.json 2>/dev/null || true
fi
# Stop/start — tear down Python and nmap in the service cgroup (see KillMode in setup unit).
sudo systemctl stop surveytrace-collector || true
sleep 2
if systemctl is-active --quiet surveytrace-collector 2>/dev/null; then
  echo "surveytrace-collector: still active after stop; sending SIGKILL to unit cgroup..."
  sudo systemctl kill -s SIGKILL surveytrace-collector || true
  sleep 1
fi
sudo systemctl start surveytrace-collector
sudo systemctl is-active --quiet surveytrace-collector && echo "collector: running" || echo "collector: FAILED"
