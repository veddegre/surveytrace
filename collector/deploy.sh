#!/usr/bin/env bash
# Deploy updated collector runtime files to an existing collector node.
# Usually invoked via repo-root deploy.sh (which auto-detects master vs collector).
set -euo pipefail

DEST="/opt/surveytrace"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_ROLE_FILE="$DEST/data/.install_role"

st_sudo() { sudo "$@"; }
VERIFY_OK=1
VERIFY_WARN=0

check_file() {
  local p="$1" label="$2"
  if st_sudo test -f "$p" >/dev/null 2>&1; then
    echo "  [OK] $label"
  else
    echo "  [FAIL] $label (missing: $p)"
    VERIFY_OK=0
  fi
}
check_dir() {
  local p="$1" label="$2"
  if st_sudo test -d "$p" >/dev/null 2>&1; then
    echo "  [OK] $label"
  else
    echo "  [FAIL] $label (missing: $p)"
    VERIFY_OK=0
  fi
}
check_owner_group() {
  local p="$1" want="$2" label="$3"
  local got
  got=$(st_sudo stat -c '%U:%G' "$p" 2>/dev/null || echo "missing")
  if [[ "$got" == "$want" ]]; then
    echo "  [OK] $label"
  else
    echo "  [FAIL] $label (got $got, want $want)"
    VERIFY_OK=0
  fi
}
check_mode() {
  local p="$1" want="$2" label="$3"
  local got
  got=$(st_sudo stat -c '%a' "$p" 2>/dev/null || echo "missing")
  if [[ "$got" == "$want" ]]; then
    echo "  [OK] $label"
  else
    echo "  [FAIL] $label (got $got, want $want)"
    VERIFY_OK=0
  fi
}
check_as_user() {
  local user="$1" expr="$2" label="$3"
  if st_sudo -u "$user" sh -lc "$expr" >/dev/null 2>&1; then
    echo "  [OK] $label"
  else
    echo "  [FAIL] $label"
    VERIFY_OK=0
  fi
}
warn_check() {
  echo "  [WARN] $*"
  VERIFY_WARN=$((VERIFY_WARN + 1))
}

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
# Collector nodes do not install master api/ (no zabbix_*_worker.php here); permissions
# are surveytrace:surveytrace under $DEST/daemon and $DEST/sql only.
sudo mkdir -p "$DEST/daemon" "$DEST/sql" "$DEST/daemon/sources"

COLLECTOR_DAEMON_LIST="$SRC/collector/collector_daemon_py_files.txt"
if [[ ! -f "$COLLECTOR_DAEMON_LIST" ]]; then
  die_collector_deploy "missing $COLLECTOR_DAEMON_LIST (repo checkout incomplete?)"
fi
while IFS= read -r _daemon_py || [[ -n "$_daemon_py" ]]; do
  _daemon_py="${_daemon_py%%#*}"
  _daemon_py="${_daemon_py#"${_daemon_py%%[![:space:]]*}"}"
  _daemon_py="${_daemon_py%"${_daemon_py##*[![:space:]]}"}"
  [[ -z "$_daemon_py" ]] && continue
  if [[ ! -f "$SRC/daemon/$_daemon_py" ]]; then
    die_collector_deploy "missing $SRC/daemon/$_daemon_py (update collector_daemon_py_files.txt?)"
  fi
  sudo cp "$SRC/daemon/$_daemon_py" "$DEST/daemon/"
done < "$COLLECTOR_DAEMON_LIST"
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

echo "Running collector post-deploy checks..."
check_dir "$DEST" "collector install root exists"
check_dir "$DEST/daemon" "collector daemon directory exists"
check_dir "$DEST/sql" "collector sql directory exists"
check_dir "$DEST/data" "collector data directory exists"
check_dir "/etc/surveytrace" "collector config directory exists"
check_file "/etc/surveytrace/collector.json" "collector config file exists"
check_file "/etc/systemd/system/surveytrace-collector.service" "collector systemd unit exists"
while IFS= read -r _daemon_py || [[ -n "$_daemon_py" ]]; do
  _daemon_py="${_daemon_py%%#*}"
  _daemon_py="${_daemon_py#"${_daemon_py%%[![:space:]]*}"}"
  _daemon_py="${_daemon_py%"${_daemon_py##*[![:space:]]}"}"
  [[ -z "$_daemon_py" ]] && continue
  check_file "$DEST/daemon/$_daemon_py" "daemon/$_daemon_py exists"
done < "$COLLECTOR_DAEMON_LIST"
check_file "$DEST/sql/schema.sql" "schema.sql exists"
check_owner_group "$DEST/daemon" "surveytrace:surveytrace" "collector daemon owner/group"
check_owner_group "/etc/surveytrace/collector.json" "root:surveytrace" "collector config owner/group"
check_mode "$DEST/daemon" "750" "collector daemon mode"
check_mode "/etc/surveytrace/collector.json" "660" "collector config mode"
check_as_user "surveytrace" "test -r \"$DEST/daemon/collector_agent.py\"" "surveytrace readable: collector_agent.py"
check_as_user "surveytrace" "test -x \"$DEST/venv/bin/python3\"" "surveytrace executable: venv python3"
check_as_user "surveytrace" "test -r /etc/surveytrace/collector.json" "surveytrace readable: collector.json"

if sudo systemctl is-enabled surveytrace-collector >/dev/null 2>&1; then
  echo "  [OK] surveytrace-collector enabled"
else
  warn_check "surveytrace-collector not enabled"
fi

if [ "$VERIFY_OK" -eq 1 ]; then
  echo "Collector post-deploy checks: PASS (${VERIFY_WARN} warning(s))"
else
  echo "Collector post-deploy checks: FAIL"
  exit 1
fi
