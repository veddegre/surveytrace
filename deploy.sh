#!/bin/bash
# SurveyTrace deploy script
# Copies source from the repo to /opt/surveytrace and restarts the right services.
# After setup.sh, the same script is used everywhere: it detects master vs collector
# and either syncs the full app or runs collector/deploy.sh.
# Run from the repo:  bash deploy.sh
# Non-interactive / automation: SURVEYTRACE_DEPLOY=master|collector forces the mode
# when the host could be ambiguous (rare). SURVEYTRACE_SKIP_INSTALL_ROLE_CHECK=1
# ignores .install_role vs chosen mode mismatches (emergency only).
set -e

DEST="/opt/surveytrace"
SRC="$(cd "$(dirname "$0")" && pwd)"
INSTALL_ROLE_FILE="$DEST/data/.install_role"

# Forward stderr for real failures (probes use explicit 2>/dev/null on the test line).
st_sudo() { sudo "$@"; }

read_install_role() {
  local r=""
  if sudo test -f "$INSTALL_ROLE_FILE" 2>/dev/null; then
    r=$(sudo cat "$INSTALL_ROLE_FILE" 2>/dev/null | tr -d '[:space:]' || echo "")
  fi
  printf '%s' "$r"
}

# True only when master setup.sh has finished (paths under DEST + systemd).
master_setup_complete() {
  st_sudo test -d "$DEST/venv" \
    && st_sudo test -f "$DEST/api/db.php" \
    && st_sudo test -f "$DEST/data/surveytrace.db" \
    && st_sudo test -f /etc/systemd/system/surveytrace-daemon.service
}

# True only when collector setup has finished (no master API tree).
collector_setup_complete() {
  st_sudo test -d "$DEST/venv" \
    && st_sudo test -f "$DEST/daemon/collector_agent.py" \
    && st_sudo test -f /etc/surveytrace/collector.json \
    && st_sudo test -f /etc/systemd/system/surveytrace-collector.service \
    && ! st_sudo test -f "$DEST/api/db.php"
}

die_deploy() { echo "$*" >&2; exit 1; }

role=$(read_install_role)
dep="$(printf '%s' "${SURVEYTRACE_DEPLOY:-}" | tr '[:upper:]' '[:lower:]')"
forced=""
case "$dep" in
  master|full|server) forced="master" ;;
  collector|agent) forced="collector" ;;
  "") ;;
  *) die_deploy "SURVEYTRACE_DEPLOY must be master or collector (got: ${SURVEYTRACE_DEPLOY})" ;;
esac

MODE=""

if [[ -n "$forced" ]]; then
  MODE="$forced"
  if [[ "$MODE" == "master" ]] && ! master_setup_complete; then
    die_deploy "SURVEYTRACE_DEPLOY=master but this host does not look like a finished master install (need $DEST/venv, $DEST/api/db.php, $DEST/data/surveytrace.db, /etc/systemd/system/surveytrace-daemon.service). Run: sudo bash \"$SRC/setup.sh\" (option 1) or SURVEYTRACE_SETUP=master"
  fi
  if [[ "$MODE" == "collector" ]] && ! collector_setup_complete; then
    die_deploy "SURVEYTRACE_DEPLOY=collector but this host does not look like a finished collector install (need $DEST/venv, $DEST/daemon/collector_agent.py, /etc/surveytrace/collector.json, surveytrace-collector.service, and no $DEST/api/db.php). Run: sudo bash \"$SRC/setup.sh\" (option 2) or sudo bash \"$SRC/collector/setup.sh\""
  fi
elif [[ "${SURVEYTRACE_SKIP_INSTALL_ROLE_CHECK:-}" == 1 ]]; then
  if master_setup_complete; then
    MODE=master
  elif collector_setup_complete; then
    MODE=collector
  fi
else
  if [[ "$role" == "collector" ]]; then
    if collector_setup_complete; then
      MODE=collector
    else
      die_deploy "This host is marked collector-only ($INSTALL_ROLE_FILE) but collector setup looks incomplete. Re-run: sudo bash \"$SRC/collector/setup.sh\""
    fi
  elif [[ "$role" == "master" ]]; then
    if master_setup_complete; then
      MODE=master
    else
      die_deploy "This host is marked master ($INSTALL_ROLE_FILE) but master setup looks incomplete. Re-run: sudo bash \"$SRC/setup.sh\" (option 1)"
    fi
  elif master_setup_complete; then
    MODE=master
  elif collector_setup_complete; then
    MODE=collector
  fi
fi

[[ -n "$MODE" ]] || die_deploy "SurveyTrace does not appear installed on this host (run setup first).

  Full server:  sudo bash \"$SRC/setup.sh\"  (choose 1)  or  SURVEYTRACE_SETUP=master sudo bash \"$SRC/setup.sh\"
  Collector:    sudo bash \"$SRC/setup.sh\"  (choose 2)  or  sudo bash \"$SRC/collector/setup.sh\"

Expected for master deploy: $DEST/venv, $DEST/api/db.php, $DEST/data/surveytrace.db, surveytrace-daemon.service
Expected for collector deploy: $DEST/venv, $DEST/daemon/collector_agent.py, /etc/surveytrace/collector.json, surveytrace-collector.service, and no $DEST/api/db.php

If the install is correct but detection is wrong: SURVEYTRACE_DEPLOY=master|collector bash deploy.sh
Override role mismatches only in emergencies: SURVEYTRACE_SKIP_INSTALL_ROLE_CHECK=1"

if [[ "${SURVEYTRACE_SKIP_INSTALL_ROLE_CHECK:-}" != 1 ]]; then
  if [[ -n "$role" ]] && [[ "$role" != "$MODE" ]]; then
    die_deploy "Chosen deploy mode ($MODE) does not match $INSTALL_ROLE_FILE (role: $role). Fix the marker or use the matching script. Emergency override: SURVEYTRACE_SKIP_INSTALL_ROLE_CHECK=1 bash deploy.sh"
  fi
fi

if [[ "$MODE" == "collector" ]]; then
  echo "Detected collector install — syncing collector files..."
  exec bash "$SRC/collector/deploy.sh"
fi

echo "Deploying SurveyTrace (master) from $SRC to $DEST..."

# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
# When adding api/*.php endpoints or libraries, append here (deploy does not
# mirror the whole api/ tree — explicit list avoids shipping dev-only files).
API_FILES=(
  st_version.php
  db.php
  lib_ai_cloud.php
  ai_actions.php
  assets.php
  change_alerts.php
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
  schedule_cron.php
  enrichment.php
  dashboard.php
  feeds.php
  feed_sync_lib.php
  lib_collectors.php
  lib_credentialed_checks.php
  lib_secrets.php
  lib_credential_profiles.php
  lib_credential_check_ops.php
  lib_credential_profile_transport_test.php
  collector_checkin.php
  credential_profiles.php
  credential_check_jobs.php
  credential_check_runs.php
  collector_jobs.php
  collector_submit.php
  collectors.php
  credentialed_checks.php
  scan_history.php
  scan_priority.php
  logout.php
  settings.php
  health.php
  export.php
  devices.php
  lib_reporting_event_model.php
  lib_integrations_outbound.php
  lib_integrations.php
  lib_rate_limit.php
  lib_reconciliation.php
  lib_worker_jobs.php
  integrations.php
  integrations_metrics.php
  integrations_events.php
  integrations_report_summary.php
  integrations_dashboard.php
  lib_integrations_dashboard.php
  lib_reporting.php
  lib_scan_scopes.php
  lib_zabbix.php
  zabbix.php
  zabbix_sync_worker.php
  zabbix_output_worker.php
  scan_scopes.php
  scopes.php
  reporting.php
  reporting_cli.php
  recon_diagnostics.php
)
for f in "${API_FILES[@]}"; do
  sudo cp "$SRC/api/$f" "$DEST/api/"
done
[ -f "$SRC/VERSION" ] && sudo cp "$SRC/VERSION" "$DEST/"
echo "  API files deployed"

# ---------------------------------------------------------------------------
# Starter integrations (Splunk / Grafana) — optional copy for operators
# ---------------------------------------------------------------------------
if [[ -d "$SRC/integrations/starter" ]]; then
  sudo mkdir -p "$DEST/integrations-starter"
  # -a preserves modes (e.g. +x on bin/surveytrace_events.py) where the filesystem allows.
  sudo cp -a "$SRC/integrations/starter/." "$DEST/integrations-starter/"
  if [[ -f "$DEST/integrations-starter/splunk_surveytrace/bin/surveytrace_events.py" ]]; then
    sudo chmod +x "$DEST/integrations-starter/splunk_surveytrace/bin/surveytrace_events.py"
  fi
  echo "  integrations-starter packaged to $DEST/integrations-starter"
fi

# ---------------------------------------------------------------------------
# Docs (operator reference; same tree as setup.sh api/daemon/public/sql/docs)
# ---------------------------------------------------------------------------
if [[ -d "$SRC/docs" ]]; then
  sudo mkdir -p "$DEST/docs"
  sudo cp -a "$SRC/docs/." "$DEST/docs/"
  echo "  docs deployed"
fi

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
  sqlite_pragmas.py
  surveytrace_paths.py
  surveytrace_version.py
  scanner_daemon.py
  recon_observations.py
  worker_jobs.py
  change_detection.py
  asset_lifecycle.py
  finding_triage.py
  scheduler_daemon.py
  ai_cloud_client.py
  fingerprint.py
  profiles.py
  cred_transport_cli.py
  cred_transport_ssh.py
  cred_transport_snmp.py
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
[ -f "$SRC/daemon/sync_cve_intel.py" ] && sudo cp "$SRC/daemon/sync_cve_intel.py" "$DEST/daemon/"
[ -f "$SRC/daemon/collector_ingest_worker.py" ] && sudo cp "$SRC/daemon/collector_ingest_worker.py" "$DEST/daemon/"
[ -f "$SRC/daemon/collector_ingest_mirror.py" ] && sudo cp "$SRC/daemon/collector_ingest_mirror.py" "$DEST/daemon/"
[ -f "$SRC/daemon/credential_check_worker.py" ] && sudo cp "$SRC/daemon/credential_check_worker.py" "$DEST/daemon/"
[ -f "$SRC/daemon/cred_check_run.py" ] && sudo cp "$SRC/daemon/cred_check_run.py" "$DEST/daemon/"
[ -f "$SRC/daemon/cred_check_ssh_os_release.py" ] && sudo cp "$SRC/daemon/cred_check_ssh_os_release.py" "$DEST/daemon/"
[ -f "$SRC/daemon/cred_check_ssh_packages.py" ] && sudo cp "$SRC/daemon/cred_check_ssh_packages.py" "$DEST/daemon/"
[ -f "$SRC/daemon/cred_check_snmp_identity.py" ] && sudo cp "$SRC/daemon/cred_check_snmp_identity.py" "$DEST/daemon/"
[ -f "$SRC/daemon/cred_secret_decrypt.py" ] && sudo cp "$SRC/daemon/cred_secret_decrypt.py" "$DEST/daemon/"
[ -f "$SRC/daemon/cred_check_slice7_selftest.py" ] && sudo cp "$SRC/daemon/cred_check_slice7_selftest.py" "$DEST/daemon/"
[ -f "$SRC/daemon/cred_check_slice8_pkg_selftest.py" ] && sudo cp "$SRC/daemon/cred_check_slice8_pkg_selftest.py" "$DEST/daemon/"
[ -f "$SRC/daemon/cred_check_slice9_snmp_selftest.py" ] && sudo cp "$SRC/daemon/cred_check_slice9_snmp_selftest.py" "$DEST/daemon/"
[ -f "$SRC/daemon/cred_decrypt_cli.php" ] && sudo cp "$SRC/daemon/cred_decrypt_cli.php" "$DEST/daemon/"

echo "  Daemon files deployed"

# ---------------------------------------------------------------------------
# Syntax validation (trusted-data / scan observation helpers)
# ---------------------------------------------------------------------------
if command -v php >/dev/null 2>&1; then
  if st_sudo php -l "$DEST/api/lib_reconciliation.php" >/dev/null 2>&1 \
    && st_sudo php -l "$DEST/api/recon_diagnostics.php" >/dev/null 2>&1 \
    && st_sudo php -l "$DEST/api/lib_worker_jobs.php" >/dev/null 2>&1 \
    && st_sudo php -l "$DEST/api/lib_credentialed_checks.php" >/dev/null 2>&1 \
    && st_sudo php -l "$DEST/api/credentialed_checks.php" >/dev/null 2>&1 \
    && st_sudo php -l "$DEST/api/lib_secrets.php" >/dev/null 2>&1 \
    && st_sudo php -l "$DEST/api/lib_credential_profiles.php" >/dev/null 2>&1 \
    && st_sudo php -l "$DEST/api/lib_credential_check_ops.php" >/dev/null 2>&1 \
    && st_sudo php -l "$DEST/api/credential_profiles.php" >/dev/null 2>&1 \
    && st_sudo php -l "$DEST/api/credential_check_jobs.php" >/dev/null 2>&1 \
    && st_sudo php -l "$DEST/api/credential_check_runs.php" >/dev/null 2>&1 \
    && st_sudo php -l "$DEST/api/lib_credential_profile_transport_test.php" >/dev/null 2>&1 \
    && st_sudo php -l "$DEST/daemon/cred_decrypt_cli.php" >/dev/null 2>&1; then
    echo "  PHP syntax OK (lib_reconciliation.php, recon_diagnostics.php, lib_worker_jobs.php, lib_credentialed_checks.php, credentialed_checks.php, lib_secrets.php, lib_credential_profiles.php, lib_credential_check_ops.php, lib_credential_profile_transport_test.php, credential_profiles.php, credential_check_jobs.php, credential_check_runs.php)"
  else
    echo "  [FAIL] php -l reconciliation / worker_jobs / cred checks API — fix syntax before relying on deploy"
    exit 1
  fi
else
  echo "  [WARN] php not in PATH — skipped php -l for reconciliation / worker_jobs API files"
fi
if command -v python3 >/dev/null 2>&1; then
  if st_sudo python3 -m py_compile "$DEST/daemon/recon_observations.py" >/dev/null 2>&1 \
    && st_sudo python3 -m py_compile "$DEST/daemon/worker_jobs.py" >/dev/null 2>&1 \
    && st_sudo python3 -m py_compile "$DEST/daemon/collector_ingest_mirror.py" >/dev/null 2>&1 \
    && st_sudo python3 -m py_compile "$DEST/daemon/cred_transport_cli.py" >/dev/null 2>&1 \
    && st_sudo python3 -m py_compile "$DEST/daemon/cred_transport_ssh.py" >/dev/null 2>&1 \
    && st_sudo python3 -m py_compile "$DEST/daemon/cred_transport_snmp.py" >/dev/null 2>&1 \
    && st_sudo python3 -m py_compile "$DEST/daemon/credential_check_worker.py" >/dev/null 2>&1 \
    && st_sudo python3 -m py_compile "$DEST/daemon/cred_check_run.py" >/dev/null 2>&1 \
    && st_sudo python3 -m py_compile "$DEST/daemon/cred_check_ssh_os_release.py" >/dev/null 2>&1 \
    && st_sudo python3 -m py_compile "$DEST/daemon/cred_check_ssh_packages.py" >/dev/null 2>&1 \
    && st_sudo python3 -m py_compile "$DEST/daemon/cred_check_snmp_identity.py" >/dev/null 2>&1 \
    && st_sudo python3 -m py_compile "$DEST/daemon/cred_secret_decrypt.py" >/dev/null 2>&1 \
    && st_sudo python3 -m py_compile "$DEST/daemon/cred_check_slice7_selftest.py" >/dev/null 2>&1 \
    && st_sudo python3 -m py_compile "$DEST/daemon/cred_check_slice8_pkg_selftest.py" >/dev/null 2>&1 \
    && st_sudo python3 -m py_compile "$DEST/daemon/cred_check_slice9_snmp_selftest.py" >/dev/null 2>&1; then
    echo "  Python syntax OK (recon_observations.py, worker_jobs.py, collector_ingest_mirror.py, cred_transport_*.py, credential_check_worker.py, cred_check_*.py)"
  else
    echo "  [FAIL] python3 -m py_compile recon_observations.py / worker_jobs.py / collector_ingest_mirror.py"
    exit 1
  fi
else
  echo "  [WARN] python3 not in PATH — skipped py_compile recon_observations.py / worker_jobs.py"
fi

# ---------------------------------------------------------------------------
# Permission sanity for UI-triggered feed sync + daemon runtime
#
# SQLite WAL mode writes the main DB plus optional sidecars in the SAME directory:
#   surveytrace.db, surveytrace.db-wal, surveytrace.db-shm
# The directory must be writable by every process that opens the DB (surveytrace
# daemons + www-data for PHP). setup.sh uses setgid 2770 on data/ so new WAL/SHM
# files inherit group www-data; deploy normalizes ownership on existing sidecars.
# ---------------------------------------------------------------------------
if id surveytrace >/dev/null 2>&1; then
  sudo usermod -aG surveytrace www-data 2>/dev/null || true
  sudo chown -R surveytrace:www-data "$DEST/api" 2>/dev/null || true
  sudo find "$DEST/api" -type d -exec chmod 2750 {} \; 2>/dev/null || true
  sudo find "$DEST/api" -type f -exec chmod 640 {} \; 2>/dev/null || true
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
  for _dbx in "$DEST/data/surveytrace.db-wal" "$DEST/data/surveytrace.db-shm"; do
    if st_sudo test -f "$_dbx"; then
      st_sudo chown surveytrace:www-data "$_dbx" 2>/dev/null || true
      st_sudo chmod 660 "$_dbx" 2>/dev/null || true
    fi
  done
fi

# ---------------------------------------------------------------------------
# SQLite migrations (PHP) — idempotent ALTERs in api/db.php
# Run once as www-data so schema matches before daemons restart (avoids rare races
# on first writer after deploy). If this fails, migrations still apply on first web hit.
# ---------------------------------------------------------------------------
if [[ -f "$DEST/api/db.php" ]] && command -v php >/dev/null 2>&1; then
  if st_sudo env -C "$DEST" php -r 'require "api/db.php"; st_db();' 2>/dev/null; then
    echo "  PHP DB bootstrap (migrations) OK"
  else
    echo "  [WARN] PHP bootstrap skipped or failed — open the UI once or restart php-fpm so api/db.php migrations run"
  fi
fi

# ---------------------------------------------------------------------------
# SQL schema (reference only — don't re-apply to existing DB)
# ---------------------------------------------------------------------------
sudo cp "$SRC/sql/schema.sql" "$DEST/sql/"
echo "  Schema file updated"

# ---------------------------------------------------------------------------
# Master: collector ingest worker (systemd unit)
# ---------------------------------------------------------------------------
install_unit_with_install_dir() {
  local unit_name="$1"
  local src_unit="$SRC/$unit_name"
  local dst_unit="/etc/systemd/system/$unit_name"
  if [ ! -f "$src_unit" ]; then
    return 0
  fi
  sudo sed -e "s|/opt/surveytrace|$DEST|g" "$src_unit" > "$dst_unit"
  sudo systemctl daemon-reload
  sudo systemctl enable "$unit_name" >/dev/null 2>&1 || true
  echo "  $unit_name installed/enabled"
}

install_unit_with_install_dir "surveytrace-collector-ingest.service"
install_unit_with_install_dir "surveytrace-credential-check-worker.service"

# ---------------------------------------------------------------------------
# Restart daemons
# ---------------------------------------------------------------------------
echo "Restarting daemons..."
sudo systemctl restart surveytrace-daemon
sudo systemctl restart surveytrace-scheduler
sudo systemctl restart surveytrace-collector-ingest.service || true
sudo systemctl restart surveytrace-credential-check-worker.service || true

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

if sudo systemctl is-active --quiet surveytrace-collector-ingest.service; then
  echo "  surveytrace-collector-ingest: running"
else
  echo "  surveytrace-collector-ingest: FAILED or inactive"
fi

if sudo systemctl cat surveytrace-credential-check-worker.service >/dev/null 2>&1; then
  if sudo systemctl is-active --quiet surveytrace-credential-check-worker.service; then
    echo "  surveytrace-credential-check-worker: running"
  else
    echo "  surveytrace-credential-check-worker: inactive or failed (optional)"
  fi
else
  echo "  surveytrace-credential-check-worker: unit not installed"
fi

# ---------------------------------------------------------------------------
# Post-deploy verification
# ---------------------------------------------------------------------------
echo "Running post-deploy checks..."
VERIFY_OK=1
VERIFY_WARN=0

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

check_dir() {
  local p="$1"
  local label="$2"
  local ok=1
  if [ "$(id -u)" -eq 0 ]; then
    [ -d "$p" ] || ok=0
  else
    sudo test -d "$p" >/dev/null 2>&1 || ok=0
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

check_owner_group() {
  local p="$1" want="$2" label="$3"
  local got
  if [ "$(id -u)" -eq 0 ]; then
    got=$(stat -c '%U:%G' "$p" 2>/dev/null || echo "missing")
  else
    got=$(sudo stat -c '%U:%G' "$p" 2>/dev/null || echo "missing")
  fi
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
  if [ "$(id -u)" -eq 0 ]; then
    got=$(stat -c '%a' "$p" 2>/dev/null || echo "missing")
  else
    got=$(sudo stat -c '%a' "$p" 2>/dev/null || echo "missing")
  fi
  if [[ "$got" == "$want" ]]; then
    echo "  [OK] $label"
  else
    echo "  [FAIL] $label (got $got, want $want)"
    VERIFY_OK=0
  fi
}

check_warn_msg() {
  echo "  [WARN] $*"
  VERIFY_WARN=$((VERIFY_WARN + 1))
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

check_file "$DEST/VERSION" "VERSION (release semver)"
check_dir "$DEST" "install root exists"
check_dir "$DEST/api" "api dir exists"
check_dir "$DEST/public" "public dir exists"
check_dir "$DEST/daemon" "daemon dir exists"
check_dir "$DEST/data" "data dir exists"
check_file "$DEST/api/st_version.php" "st_version.php (ST_VERSION loader)"
check_file "$DEST/api/lib_reconciliation.php" "lib_reconciliation.php (trusted data)"
check_file "$DEST/api/lib_worker_jobs.php" "lib_worker_jobs.php (worker execution substrate)"
check_file "$DEST/api/recon_diagnostics.php" "recon_diagnostics.php"
check_file "$DEST/api/health.php" "health API"
check_file "$DEST/api/feeds.php" "feeds API"
check_file "$DEST/api/feed_sync_lib.php" "feed_sync_lib"
check_file "$DEST/api/lib_collectors.php" "lib_collectors"
check_file "$DEST/api/lib_credentialed_checks.php" "lib_credentialed_checks (plugin registry)"
check_file "$DEST/api/lib_secrets.php" "lib_secrets (credential envelope crypto)"
check_file "$DEST/api/lib_credential_profiles.php" "lib_credential_profiles (credential metadata)"
check_file "$DEST/api/lib_rate_limit.php" "lib_rate_limit"
check_file "$DEST/api/collector_checkin.php" "collector_checkin API"
check_file "$DEST/api/collector_jobs.php" "collector_jobs API"
check_file "$DEST/api/collector_submit.php" "collector_submit API"
check_file "$DEST/api/collectors.php" "collectors API"
check_file "$DEST/api/credentialed_checks.php" "credentialed_checks API (plugin registry)"
check_file "$DEST/api/credential_profiles.php" "credential_profiles API"
check_file "$DEST/api/lib_credential_check_ops.php" "lib_credential_check_ops (cred check jobs/runs)"
check_file "$DEST/api/credential_check_jobs.php" "credential_check_jobs API"
check_file "$DEST/api/credential_check_runs.php" "credential_check_runs API"
check_file "$DEST/api/lib_credential_profile_transport_test.php" "lib_credential_profile_transport_test (handshake runner)"
check_file "$DEST/daemon/cred_transport_cli.py" "cred_transport_cli.py"
check_file "$DEST/daemon/cred_transport_ssh.py" "cred_transport_ssh.py"
check_file "$DEST/daemon/cred_transport_snmp.py" "cred_transport_snmp.py"
check_file "$DEST/api/scan_history.php" "scan history API"
check_file "$DEST/api/lib_scan_scopes.php" "lib_scan_scopes (scoped reporting)"
check_file "$DEST/api/scan_scopes.php" "scan_scopes API"
check_file "$DEST/api/scopes.php" "scopes API (catalog + CRUD + asset counts)"
check_file "$DEST/api/change_alerts.php" "change_alerts API"
check_file "$DEST/api/scan_priority.php" "scan priority API"
check_file "$DEST/api/devices.php" "devices API"
check_file "$DEST/api/lib_ai_cloud.php" "lib_ai_cloud (cloud AI)"
check_file "$DEST/api/ai_actions.php" "ai_actions API"
check_file "$DEST/daemon/ai_cloud_client.py" "ai_cloud_client (scanner cloud AI)"
check_file "$DEST/daemon/feed_sync_worker.php" "feed_sync_worker (UI sync)"
check_file "$DEST/daemon/feed_sync_cancel.py" "feed_sync_cancel"
check_file "$DEST/daemon/sync_nvd.py" "sync_nvd.py"
check_file "$DEST/daemon/sync_oui.py" "sync_oui.py"
check_file "$DEST/daemon/sync_webfp.py" "sync_webfp.py"
check_file "$DEST/daemon/sync_cve_intel.py" "sync_cve_intel.py"
check_file "$DEST/daemon/collector_ingest_worker.py" "collector_ingest_worker.py"
check_file "$DEST/daemon/collector_ingest_mirror.py" "collector_ingest_mirror.py (worker mirror)"
check_file "$DEST/daemon/credential_check_worker.py" "credential_check_worker.py (cred checks placeholder)"
check_file "$DEST/daemon/asset_lifecycle.py" "asset_lifecycle.py"
check_file "$DEST/daemon/recon_observations.py" "recon_observations.py (scan → observations)"
check_file "$DEST/daemon/worker_jobs.py" "worker_jobs.py (worker execution substrate helpers)"
check_file "$DEST/data/surveytrace.db" "surveytrace.db"
check_file "$DEST/docs/TRUSTED_DATA_MODEL.md" "docs/TRUSTED_DATA_MODEL.md"
check_file "$DEST/docs/CREDENTIALED_CHECKS_ENGINE.md" "docs/CREDENTIALED_CHECKS_ENGINE.md"
check_file "$DEST/docs/CREDENTIALED_CHECKS_MVP_PLAN.md" "docs/CREDENTIALED_CHECKS_MVP_PLAN.md"
check_file "/etc/cron.d/surveytrace-nvd" "NVD cron"
check_file "/etc/cron.d/surveytrace-fp" "fingerprint cron"

check_as_user "surveytrace" "test -f \"$DEST/api/zabbix_sync_worker.php\" && test -r \"$DEST/api/zabbix_sync_worker.php\"" \
  "surveytrace read: api/zabbix_sync_worker.php"
check_as_user "surveytrace" "test -f \"$DEST/api/zabbix_output_worker.php\" && test -r \"$DEST/api/zabbix_output_worker.php\"" \
  "surveytrace read: api/zabbix_output_worker.php"
check_as_user "www-data" "test -r \"$DEST/api/zabbix_sync_worker.php\"" \
  "www-data read: api/zabbix_sync_worker.php"
check_as_user "www-data" "test -r \"$DEST/api/zabbix_output_worker.php\"" \
  "www-data read: api/zabbix_output_worker.php"
check_as_user "www-data" "test -r \"$DEST/daemon/feed_sync_worker.php\"" \
  "www-data read: feed_sync_worker.php"
check_as_user "www-data" "test -r \"$DEST/daemon/sync_nvd.py\"" \
  "www-data read: sync_nvd.py"
check_as_user "www-data" "test -r \"$DEST/daemon/sync_oui.py\"" \
  "www-data read: sync_oui.py"
check_as_user "www-data" "test -r \"$DEST/daemon/sync_webfp.py\"" \
  "www-data read: sync_webfp.py"
check_as_user "www-data" "test -r \"$DEST/daemon/sync_cve_intel.py\"" \
  "www-data read: sync_cve_intel.py"
check_as_user "www-data" "test -w \"$DEST/data\"" \
  "www-data write: data/"
check_as_user "surveytrace" "test -w \"$DEST/data\"" \
  "surveytrace write: data/"

check_owner_group "$DEST/api" "surveytrace:www-data" "api owner/group"
check_mode "$DEST/api" "2750" "api mode"
check_owner_group "$DEST/data" "surveytrace:www-data" "data owner/group"
check_mode "$DEST/data" "2770" "data mode"
check_mode "$DEST/data/surveytrace.db" "660" "surveytrace.db mode"
check_owner_group "$DEST/daemon" "surveytrace:surveytrace" "daemon owner/group"

if sudo systemctl cat surveytrace-daemon.service >/dev/null 2>&1; then
  echo "  [OK] unit present: surveytrace-daemon.service"
else
  echo "  [FAIL] unit missing: surveytrace-daemon.service"
  VERIFY_OK=0
fi
if sudo systemctl cat surveytrace-scheduler.service >/dev/null 2>&1; then
  echo "  [OK] unit present: surveytrace-scheduler.service"
else
  echo "  [FAIL] unit missing: surveytrace-scheduler.service"
  VERIFY_OK=0
fi
if sudo systemctl cat surveytrace-collector-ingest.service >/dev/null 2>&1; then
  echo "  [OK] unit present: surveytrace-collector-ingest.service"
else
  echo "  [FAIL] unit missing: surveytrace-collector-ingest.service"
  VERIFY_OK=0
fi
for _st_unit in surveytrace-daemon.service surveytrace-scheduler.service surveytrace-collector-ingest.service surveytrace-credential-check-worker.service; do
  if sudo systemctl cat "$_st_unit" 2>/dev/null | grep -Eq '^ReadWritePaths=.*/data'; then
    echo "  [OK] unit writable data path: $_st_unit"
  else
    echo "  [FAIL] unit missing ReadWritePaths=/opt/surveytrace/data: $_st_unit"
    VERIFY_OK=0
  fi
done

if command -v zabbix_sender >/dev/null 2>&1; then
  echo "  [OK] zabbix_sender available"
else
  check_warn_msg "zabbix_sender not found; install zabbix-sender on Debian/Ubuntu to use SurveyTrace -> Zabbix output."
fi

if [ "$VERIFY_OK" -eq 1 ]; then
  echo "  Post-deploy checks: PASS (${VERIFY_WARN} warning(s))"
else
  echo "  Post-deploy checks: FAIL (see lines above)"
  exit 1
fi

echo ""
echo "Deploy complete."
