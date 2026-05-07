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

## Worker substrate (System health — Background jobs preview)

The **Background jobs (preview)** block on **System health** is a read-only view of the SQLite **worker execution substrate** (`worker_jobs`, `worker_nodes`, `worker_heartbeats`, `worker_job_events`). It does **not** drive scanner, collector ingest, or scheduler behavior in MVP slices 1–3.

| UI / API signal | Meaning |
|-----------------|--------|
| Status **Unavailable** | Migration `migration_worker_execution_substrate_v1` not applied or tables missing — expected on older DBs until the app runs migrations. |
| Status **OK** (one quiet line) | Substrate is present and idle, or counts are healthy vs built-in thresholds. |
| Status **Warning** / **Error** | Actionable backlog or liveness issues (stale node heartbeats, failed/retrying jobs, old queued/running ages, recent error-level events). |

**What to do:** Open **System health → Needs attention** for merged hints. Inspect `worker_job_events` and job rows in SQLite only if you are diagnosing a future or lab feature — production ingest and scans still use their legacy tables and queues.

Design reference: [Worker execution MVP plan](../WORKER_EXECUTION_MVP_PLAN.md) · [Worker execution substrate](../WORKER_EXECUTION_SUBSTRATE.md).

**Collector ingest mirror (slice 4):** Successful chunk uploads also upsert a `worker_jobs` row (`job_type = collector_ingest`, `entity_type = collector_submission`, `entity_id = collector_submissions.id`) and append `worker_job_events`. The ingest **worker** and **submit** path update this mirror best-effort. **`collector_ingest_queue` and existing ingest/scan tables remain authoritative** — the worker substrate is a **read-only mirror for visibility**, not a second queue to drain. If mirror writes fail, collector ingest still proceeds; use **System health** collector ingest counts, `collector_ingest_queue`, and **Scan history** for operations. Retention / pruning of old mirror rows and events is not automated yet.

**Credentialed check runs (slice 7–9):** Launching a run inserts `worker_jobs` with `job_type = credentialed_check` and `entity_id = credential_check_runs.id`. The **`surveytrace-credential-check-worker`** service (or `daemon/credential_check_worker.py` under the app venv) **must be running** for runs to leave `queued`. The worker executes **`ssh.linux.os_release@1.0.0`** (bounded **`/etc/os-release`** over SSH — **asset IP only**) and **`ssh.linux.package_inventory@1.0.0`** when selected on **SSH** profiles (fixed **`dpkg-query`** / **`rpm -qa`** only), and **`snmpv3.device_identity@1.0.0`** on **SNMPv3** profiles (three fixed GETs: sysDescr / sysObjectID / sysName — **no walk or SET**). Mismatched plugins get **`unsupported_transport`** result rows instead of failing the whole target. Requires **`php`** on PATH for **`daemon/cred_decrypt_cli.php`** when profiles store **`secret_ciphertext`**, **`SURVEYTRACE_CRED_SECRET_KEY`** aligned with the web app, **`python3`** with **`paramiko`** (SSH) and **`pysnmp`** (SNMP execution + handshake). **`SURVEYTRACE_CRED_CHECK_PLACEHOLDER_ONLY=1`** forces no remote SNMP/SSH (smoke/CI). If runs stay queued, verify `systemctl status surveytrace-credential-check-worker` and `journalctl -u surveytrace-credential-check-worker -n 50`. Cancelling uses `cancel_requested_at` plus `st_worker_finalize_queued_cancel` / leased cancel helpers so work does not stall.

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

## Collector results and master ingest

Use this when a **collector** has finished a scan on the worker node but inventory on the master does not update yet (or shows an ingest error).

### Submitted result awaiting master ingest

**What it means:** The collector uploaded a payload; the master has queued it for **`surveytrace-collector-ingest`** (or equivalent) to merge into the database.

**What to do:**

1. **System Health** — Open **System Health** in the UI and confirm services are healthy; note any collector-ingest warnings.
2. **Service status (master):**

```bash
systemctl status surveytrace-collector-ingest
journalctl -u surveytrace-collector-ingest -n 80
```

3. **Scan History** — Open **Scan History**, select the job, and use the **detail** view for ingest / submission context (wording varies by release; look for ingest or submission state).

### Ingest retrying

**What it means:** A transient error (DB lock, short network blip) may cause automatic retry behavior depending on your build.

**What to do:** Wait briefly; if the state persists, inspect `journalctl -u surveytrace-collector-ingest` for repeated errors and check disk space and SQLite permissions on `/opt/surveytrace/data/`.

### Ingest failed

**What it means:** The master rejected or could not apply the submission (validation error, schema mismatch, or persistent I/O failure).

**What to do:**

1. Capture logs: `journalctl -u surveytrace-collector-ingest -n 100` (and collector logs on the worker if the failure is upload-side).
2. Re-run **`deploy.sh`** after upgrades so `api/` and `daemon/` match the master version (version skew is a common cause of ingest failures after git pulls).
3. Confirm **`surveytrace-collector-ingest`** is enabled and running on the **master** (not only the collector node).

### Where to look (summary)

| Symptom | Check first |
|--------|----------------|
| Stuck “submitted” / waiting | `surveytrace-collector-ingest`, System Health, Scan History detail |
| Retrying | Ingest logs, DB directory permissions, load |
| Failed | Ingest logs, version parity (`deploy.sh`), schema migrations (`api/db.php` bootstrap) |

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