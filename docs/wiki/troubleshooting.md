# Troubleshooting

[← Back to Documentation](README.md)

Common issues and how to resolve them.

## Scans

### Scan does not start

Possible causes:
- Missing permissions
- Scheduler not running
- Invalid scan config

Steps to fix:
1. Check Scan control inputs (target/profile/options).
2. Check scheduler service:
   `systemctl status surveytrace-scheduler`
3. Check recent scheduler logs:
   `journalctl -u surveytrace-scheduler -n 50`

## Zabbix

### Zabbix shows "unknown"

Cause:
- Sync not run
- Availability fields missing

Fix:
1. Run sync manually from Enrichment/Integrations.
2. Check System Health -> Zabbix status.
3. Verify host mapping in match review and linked assets.

### Zabbix not syncing

Cause:
- Scheduler issue
- API issue
- Permission issue

Fix:
1. Check scheduler logs:
   `journalctl -u surveytrace-scheduler`
2. Run worker manually from install root:
   `php api/zabbix_sync_worker.php`
3. Check API connectivity/configuration in Integrations.

## Reports

### No data in reports

Cause:
- Using job scope with no completed scans

Fix:
- Switch to inventory scope.
- Or run a scan for that scope.

## Installation / Deploy

### Setup fails

Fix:
- Re-run `setup.sh`.
- Check permissions under `/opt/surveytrace`.
- Verify expected services are running.

### Deploy fails

Fix:
- Run `deploy.sh` again.
- Check validation output for the first failing check.
- Fix permissions or missing files, then re-run deploy.

## General

### UI shows unexpected values

Fix:
- Refresh the page.
- Re-run relevant sync.
- Check System Health for service/integration status.

## When to escalate

If issues persist:
- Check service logs.
- Verify database state.
- Re-run the relevant worker manually.

---

See also:
- [Documentation home](README.md)

---
