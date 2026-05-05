# Troubleshooting

[← Back to Documentation](README.md)

Common issues and how to diagnose and resolve them.

---

## When to use this

- Use this page when:
  - scans are not running or failing
  - integrations are not working
  - reports show missing or unexpected data
  - system health indicates degraded/error state

---

## Scans

### Scan does not start

**Possible causes:**
- scheduler not running
- invalid scan input (target/profile)
- permission issues

**Steps to fix:**

1. Verify scan inputs:
   - valid CIDR or IP
   - valid scan profile

2. Check scheduler:

```bash
systemctl status surveytrace-scheduler
```

3. Check logs:

```bash
journalctl -u surveytrace-scheduler -n 50
```

---

### Scan stays queued

**Cause:**
- scheduler or scanner daemon not processing jobs

**Fix:**

```bash
systemctl status surveytrace-scheduler
systemctl status surveytrace-daemon
```

Check logs:

```bash
journalctl -u surveytrace-scheduler -n 50
```

---

### Scan fails immediately

**Cause:**
- invalid target
- network unreachable
- permission or runtime issue

**Fix:**

```bash
journalctl -u surveytrace-scheduler -n 50
```

---

### No assets after scan

**Cause:**
- no hosts discovered
- filtering in UI
- scan incomplete

**Fix:**
- confirm scan completed successfully
- review scan details
- check target reachability

---

## Zabbix

### Zabbix shows "unknown"

**Cause:**
- sync not run
- asset not matched
- availability not returned by API

**Fix:**

1. Run sync:
   - from UI **or** manually:

```bash
sudo -u surveytrace php /opt/surveytrace/api/zabbix_sync_worker.php
```

2. Verify match:
   - open Enrichment → match review
   - confirm asset is linked

3. Re-check asset details

---

### Zabbix not syncing

**Cause:**
- scheduler issue
- API issue
- configuration error

**Fix:**

1. Check logs:

```bash
journalctl -u surveytrace-scheduler -n 100
```

2. Run worker manually:

```bash
sudo -u surveytrace php /opt/surveytrace/api/zabbix_sync_worker.php
```

3. Verify API:
- correct URL (`/api_jsonrpc.php`)
- valid token
- reachable endpoint

---

### Zabbix status is Degraded or Error

**Fix:**

- run sync manually
- check last sync time
- check logs for errors

---

### Zabbix output not working

**Cause:**
- `zabbix_sender` not installed
- misconfigured output target

**Fix:**

```bash
which zabbix_sender
```

Check logs:

```bash
journalctl -u surveytrace-scheduler -n 50
```

---

## Reports

### No data in reports

**Cause:**
- using job scope with no completed scans

**Fix:**
- switch to inventory scope
- or run a scan for that scope

---

### Reports differ between modes

**Cause:**
- expected behavior (job vs inventory model)

**Fix:**
- verify correct mode is selected

---

## Installation / Deploy

### Setup fails

**Fix:**

```bash
sudo ./setup.sh
```

Check:

```bash
systemctl status surveytrace-scheduler
journalctl -u surveytrace-scheduler -n 50
```

Verify:
- `/opt/surveytrace` exists
- permissions are correct

---

### Deploy fails

**Fix:**

```bash
sudo ./deploy.sh
```

- review validation output carefully
- fix first reported failure
- re-run deploy

---

### Services not running after setup/deploy

**Fix:**

```bash
systemctl status surveytrace-scheduler
systemctl status surveytrace-daemon
systemctl status surveytrace-collector-ingest
```

---

## Database / system checks

### Verify database exists

```bash
ls -l /opt/surveytrace/data/surveytrace.db
```

---

### Inspect scan jobs

```bash
sqlite3 /opt/surveytrace/data/surveytrace.db "SELECT id, status, scope_id FROM scan_jobs ORDER BY id DESC LIMIT 10;"
```

---

### Inspect Zabbix links

```bash
sqlite3 /opt/surveytrace/data/surveytrace.db "SELECT * FROM zabbix_asset_links LIMIT 10;"
```

---

## General

### UI shows unexpected values

**Fix:**

- refresh page
- re-run relevant sync or scan
- verify System Health status

---

### Data looks stale

**Cause:**
- scheduler not running
- sync not executed

**Fix:**

```bash
systemctl status surveytrace-scheduler
```

---

## When to escalate

If issues persist:

1. Check logs:

```bash
journalctl -u surveytrace-scheduler -n 100
```

2. Verify:
- database state
- service status
- integration configuration

3. Re-run relevant worker manually

---

## Quick troubleshooting checklist

- scheduler running
- services active
- logs clean (no repeated errors)
- database accessible
- integrations configured and synced
- correct report mode selected

---

See also:
- [System Guide](system-guide.md)
- [Enrichment](enrichment.md)
- [Reporting](reporting.md)
- [Documentation home](README.md)