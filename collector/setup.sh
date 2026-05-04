#!/usr/bin/env bash
# SurveyTrace Collector setup (parity collector, passive-enabled default)
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLU}[INFO]${NC}  $*"; }
ok()    { echo -e "${GRN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }

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

mkdir -p "$INSTALL_DIR/daemon" "$INSTALL_DIR/sql" "$INSTALL_DIR/data"
printf '%s\n' collector > "$INSTALL_ROLE_FILE"
cp "$SRC_DIR/daemon/scanner_daemon.py" "$INSTALL_DIR/daemon/"
cp "$SRC_DIR/daemon/change_detection.py" "$INSTALL_DIR/daemon/"
cp "$SRC_DIR/daemon/fingerprint.py" "$INSTALL_DIR/daemon/"
cp "$SRC_DIR/daemon/profiles.py" "$INSTALL_DIR/daemon/"
cp "$SRC_DIR/daemon/ai_cloud_client.py" "$INSTALL_DIR/daemon/"
cp "$SRC_DIR/daemon/collector_agent.py" "$INSTALL_DIR/daemon/"
cp "$SRC_DIR/daemon/collector_parity_runner.py" "$INSTALL_DIR/daemon/"
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
echo "Edit $CFG_FILE and restart: systemctl restart surveytrace-collector"
