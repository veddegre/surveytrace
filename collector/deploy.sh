#!/usr/bin/env bash
# Deploy updated collector runtime files to an existing collector node.
# Usually invoked via repo-root deploy.sh (which auto-detects master vs collector).
set -euo pipefail

DEST="/opt/surveytrace"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_ROLE_FILE="$DEST/data/.install_role"

st_sudo() { sudo "$@" 2>/dev/null; }

collector_setup_complete() {
  st_sudo test -d "$DEST/venv" \
    && st_sudo test -f "$DEST/daemon/collector_agent.py" \
    && st_sudo test -f /etc/surveytrace/collector.json \
    && st_sudo test -f /etc/systemd/system/surveytrace-collector.service \
    && ! st_sudo test -f "$DEST/api/db.php"
}

die_collector_deploy() { echo "$*" >&2; exit 1; }

if [[ "${SURVEYTRACE_SKIP_INSTALL_ROLE_CHECK:-}" != 1 ]]; then
  role=""
  if sudo test -f "$INSTALL_ROLE_FILE" 2>/dev/null; then
    role=$(sudo cat "$INSTALL_ROLE_FILE" 2>/dev/null | tr -d '[:space:]' || true)
  fi
  if [[ "$role" == "master" ]]; then
    echo "Refusing collector deploy: $INSTALL_ROLE_FILE marks this host as the full SurveyTrace server." >&2
    echo "Use: bash \"$SRC/deploy.sh\"" >&2
    echo "Override (emergency only): SURVEYTRACE_SKIP_INSTALL_ROLE_CHECK=1 bash collector/deploy.sh" >&2
    exit 1
  fi
  if sudo test -f "$DEST/api/db.php" 2>/dev/null || sudo test -f "$DEST/data/surveytrace.db" 2>/dev/null; then
    echo "Refusing collector deploy: $DEST has master app files (api/db.php or data/surveytrace.db)." >&2
    echo "Use: bash \"$SRC/deploy.sh\"" >&2
    echo "Override (emergency only): SURVEYTRACE_SKIP_INSTALL_ROLE_CHECK=1 bash collector/deploy.sh" >&2
    exit 1
  fi
fi

if ! collector_setup_complete; then
  die_collector_deploy "Collector setup does not look complete on this host. Run setup first:

  sudo bash \"$SRC/setup.sh\"  (choose option 2)   or   sudo bash \"$SRC/collector/setup.sh\"

Then deploy again (from the repo):  bash \"$SRC/deploy.sh\"   or   bash \"$SRC/collector/deploy.sh\"

Expected: $DEST/venv, $DEST/daemon/collector_agent.py, /etc/surveytrace/collector.json, /etc/systemd/system/surveytrace-collector.service, and no $DEST/api/db.php"
fi

echo "Deploying SurveyTrace collector files..."
sudo mkdir -p "$DEST/daemon" "$DEST/sql" "$DEST/daemon/sources"

for f in sqlite_pragmas.py surveytrace_paths.py surveytrace_version.py scanner_daemon.py change_detection.py asset_lifecycle.py finding_triage.py fingerprint.py profiles.py ai_cloud_client.py collector_agent.py collector_parity_runner.py; do
  sudo cp "$SRC/daemon/$f" "$DEST/daemon/"
done
[ -f "$SRC/VERSION" ] && sudo cp "$SRC/VERSION" "$DEST/"
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
