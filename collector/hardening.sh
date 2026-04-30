#!/usr/bin/env bash
# Apply collector host hardening defaults.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }

echo "[INFO] Applying collector hardening..."

# Basic firewall defaults
if command -v ufw >/dev/null 2>&1; then
  ufw --force default deny incoming || true
  ufw --force default allow outgoing || true
  ufw allow ssh || true
  ufw --force enable || true
fi

# Ensure collector config only readable by root+group
if [[ -f /etc/surveytrace/collector.json ]]; then
  chown root:surveytrace /etc/surveytrace/collector.json || true
  chmod 640 /etc/surveytrace/collector.json || true
fi

# Restrict service
if [[ -f /etc/systemd/system/surveytrace-collector.service ]]; then
  systemctl daemon-reload
  systemctl restart surveytrace-collector
fi

echo "[OK] Collector hardening applied"
