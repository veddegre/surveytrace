#!/usr/bin/env bash
# SurveyTrace Collector setup (parity collector, passive-enabled default)
set -euo pipefail

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

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash collector/setup.sh"

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SRC_DIR
INSTALL_DIR="/opt/surveytrace"
DATA_DIR="$INSTALL_DIR/data"
VENV_DIR="$INSTALL_DIR/venv"
APP_USER="surveytrace"
GROUP="surveytrace"
CFG_DIR="/etc/surveytrace"
CFG_FILE="$CFG_DIR/collector.json"
INSTALL_ROLE_FILE="$DATA_DIR/.install_role"

if [[ "${SURVEYTRACE_SKIP_INSTALL_ROLE_CHECK:-}" != 1 ]]; then
  role=""
  [[ -f "$INSTALL_ROLE_FILE" ]] && role=$(tr -d '[:space:]' < "$INSTALL_ROLE_FILE" 2>/dev/null || true)
  if [[ "$role" == "master" ]]; then
    die "This host is marked as the full SurveyTrace server ($INSTALL_ROLE_FILE). Do not run collector/setup.sh here. Use the repo root: sudo bash \"$SRC_DIR/setup.sh\" or bash \"$SRC_DIR/deploy.sh\"."
  fi
  if [[ -f "$INSTALL_DIR/api/db.php" ]] || [[ -f "$DATA_DIR/surveytrace.db" ]]; then
    die "Full SurveyTrace (api/db or surveytrace.db) is already present under $INSTALL_DIR. Do not run collector/setup.sh on the master. Use: sudo bash \"$SRC_DIR/setup.sh\" or bash \"$SRC_DIR/deploy.sh\"."
  fi
fi

info "Installing collector dependencies..."
apt-get update -qq
apt-get install -y --no-install-recommends \
  python3 python3-venv python3-pip python3-dev \
  nmap tcpdump avahi-utils avahi-daemon sqlite3 \
  libssl-dev libffi-dev gcc || die "Package install failed"

if ! id "$APP_USER" &>/dev/null; then
  useradd --system --create-home --home /var/lib/surveytrace --shell /usr/sbin/nologin "$APP_USER"
fi
usermod -aG netdev "$APP_USER" 2>/dev/null || true

# No master api/ tree on collectors (no Zabbix API workers); only daemon + sql + data.
mkdir -p "$INSTALL_DIR/daemon" "$INSTALL_DIR/sql" "$INSTALL_DIR/data"
printf '%s\n' collector > "$INSTALL_ROLE_FILE"
COLLECTOR_DAEMON_LIST="$SRC_DIR/collector/collector_daemon_py_files.txt"
[[ -f "$COLLECTOR_DAEMON_LIST" ]] || die "missing $COLLECTOR_DAEMON_LIST (repo checkout incomplete?)"
while IFS= read -r _daemon_py || [[ -n "$_daemon_py" ]]; do
  _daemon_py="${_daemon_py%%#*}"
  _daemon_py="${_daemon_py#"${_daemon_py%%[![:space:]]*}"}"
  _daemon_py="${_daemon_py%"${_daemon_py##*[![:space:]]}"}"
  [[ -z "$_daemon_py" ]] && continue
  [[ -f "$SRC_DIR/daemon/$_daemon_py" ]] || die "missing daemon/$_daemon_py (update collector_daemon_py_files.txt?)"
  cp "$SRC_DIR/daemon/$_daemon_py" "$INSTALL_DIR/daemon/"
done < "$COLLECTOR_DAEMON_LIST"
cp "$SRC_DIR/sql/schema.sql" "$INSTALL_DIR/sql/"
mkdir -p "$INSTALL_DIR/daemon/sources"
cp "$SRC_DIR/daemon/sources/"*.py "$INSTALL_DIR/daemon/sources/" 2>/dev/null || true

python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -q "scapy>=2.5" "python-nmap>=0.7" "requests>=2.28" "pysnmp>=4.4"

mkdir -p "$CFG_DIR"
if [[ ! -f "$CFG_FILE" ]]; then
cat > "$CFG_FILE" <<'EOF'
{
  "server_base_url": "https://surveytrace.example.com",
  "install_token": "REPLACE_ME",
  "name": "collector-1",
  "site_label": "Site 1",
  "version": "collector-agent-parity",
  "max_jobs": 2,
  "poll_interval_sec": 20
}
EOF
fi

cat > /etc/systemd/system/surveytrace-collector.service <<'EOF'
[Unit]
Description=SurveyTrace collector agent (parity)
After=network.target
Documentation=https://github.com/yourorg/surveytrace

[Service]
Type=simple
User=surveytrace
Group=surveytrace
WorkingDirectory=/opt/surveytrace/daemon
ExecStart=/opt/surveytrace/venv/bin/python3 /opt/surveytrace/daemon/collector_agent.py --config /etc/surveytrace/collector.json
# Ensure nmap/python-nmap children die on stop/redeploy (default can miss edge cases).
KillMode=control-group
TimeoutStopSec=120
Restart=always
RestartSec=5
# Passive/active discovery: raw sockets (and some nmap modes) require CAP_NET_RAW;
# CAP_NET_ADMIN retained for parity with scanner daemon on kernels that need it.
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/surveytrace/data /etc/surveytrace /var/lib/surveytrace

[Install]
WantedBy=multi-user.target
EOF

chown -R "$APP_USER":"$GROUP" "$INSTALL_DIR" /var/lib/surveytrace
chmod 750 "$INSTALL_DIR" "$INSTALL_DIR/daemon"
chmod 660 "$CFG_FILE"
chown root:"$GROUP" "$CFG_FILE"

systemctl daemon-reload
systemctl enable --now surveytrace-collector
ok "Collector service installed and started"

info "Running collector post-install validation…"
check_dir "$INSTALL_DIR" "collector install root exists"
check_dir "$INSTALL_DIR/daemon" "collector daemon directory exists"
check_dir "$INSTALL_DIR/data" "collector data directory exists"
check_dir "$CFG_DIR" "collector config directory exists"
check_file "$CFG_FILE" "collector config file exists"
check_file "/etc/systemd/system/surveytrace-collector.service" "collector systemd unit exists"
while IFS= read -r _daemon_py || [[ -n "$_daemon_py" ]]; do
  _daemon_py="${_daemon_py%%#*}"
  _daemon_py="${_daemon_py#"${_daemon_py%%[![:space:]]*}"}"
  _daemon_py="${_daemon_py%"${_daemon_py##*[![:space:]]}"}"
  [[ -z "$_daemon_py" ]] && continue
  check_file "$INSTALL_DIR/daemon/$_daemon_py" "daemon/$_daemon_py exists"
done < "$COLLECTOR_DAEMON_LIST"
check_file "$INSTALL_DIR/sql/schema.sql" "schema.sql exists"

check_owner_group "$INSTALL_DIR/daemon" "$APP_USER:$GROUP" "collector daemon owner/group"
check_mode "$INSTALL_DIR/daemon" "750" "collector daemon mode"
check_owner_group "$CFG_FILE" "root:$GROUP" "collector config owner/group"
check_mode "$CFG_FILE" "660" "collector config mode"

check_readable_as_user "$APP_USER" "$INSTALL_DIR/daemon/collector_agent.py" "collector user readable: collector_agent.py"
check_executable_as_user "$APP_USER" "$VENV_DIR/bin/python3" "collector user executable: venv python3"
check_readable_as_user "$APP_USER" "$CFG_FILE" "collector user readable: collector.json"

if systemctl cat surveytrace-collector.service >/dev/null 2>&1; then
  check_ok "systemd unit present: surveytrace-collector.service"
else
  check_fail "systemd unit missing: surveytrace-collector.service"
fi
if systemctl is-enabled surveytrace-collector >/dev/null 2>&1; then
  check_ok "systemd unit enabled: surveytrace-collector"
else
  check_warn "systemd unit not enabled: surveytrace-collector"
fi

if [[ "$CHECK_FAIL" -gt 0 ]]; then
  die "Collector post-install validation failed with $CHECK_FAIL critical issue(s) and $CHECK_WARN warning(s)."
fi
ok "Collector post-install validation complete ($CHECK_WARN warning(s))"
echo "Edit $CFG_FILE and restart: systemctl restart surveytrace-collector"
