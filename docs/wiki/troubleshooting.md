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

## `surveytrace-scheduler` — scheduled scans stop but a restart fixes it

**Symptom:** `journalctl -u surveytrace-scheduler` repeats `sqlite3.OperationalError: unable to open database file` every poll interval, while **`sudo -u surveytrace sqlite3 /opt/surveytrace/data/surveytrace.db 'select 1'`** still works. Scheduled scans do not run until **`systemctl restart surveytrace-scheduler`**.

**Typical cause:** The long-lived Python process hits a **resource limit** (often **open file descriptors**) or otherwise gets into a state where SQLite cannot open the DB from that process only. A restart clears it.

**What we ship to reduce recurrence:**

| Mitigation | Detail |
|------------|--------|
| **`LimitNOFILE=`** in `surveytrace-scheduler.service` | Raises the soft open-file limit for the service. On master, **`sudo bash deploy.sh`** copies the repo unit into **`/etc/systemd/system/`** (with `daemon-reload`) and restarts the scheduler — see `deploy.sh` **`install_unit_with_install_dir`**. |
| **Auto-exit on repeated hard open errors** | `scheduler_daemon.py` exits with status **1** after **10** consecutive failures matching “unable to open” / “disk I/o” so **`Restart=always`** replaces the process without manual intervention. |
| **Richer connect logging** | On connect failure, logs resolved path, `exists`, parent writable, file R/W, and **`open_fds`** (from `/proc/self/fd`) to confirm FD pressure. |

**If it still recurs:** Inspect **`journalctl -u surveytrace-scheduler`** for the `sqlite connect failed:` line, compare **`open_fds`** to **`LimitNOFILE`**, and check for other services or cron jobs opening the same DB. Consider a periodic controlled restart (e.g. weekly maintenance window) only if needed after tuning limits.

---

## Credential secret helper — security model

Hardened installs keep **`SURVEYTRACE_CRED_SECRET_KEY`** out of the **php-fpm / Apache** process environment for normal **profile secret encrypt**, **clear**, and **handshake** flows. The key lives in **`/etc/surveytrace/surveytrace.env`**, readable only by the **`surveytrace`** service user — **not** by **`www-data`**.

| Requirement | Detail |
|---------------|--------|
| Directory | **`/etc/surveytrace`** — owner **`root`**, group **`surveytrace`**, mode **`0750`**. |
| Env file | **`/etc/surveytrace/surveytrace.env`** — **`root:surveytrace`**, mode **`0640`**. **`www-data` must not be able to read this file** (no ACL/grant that adds `www-data`). |
| SurveyTrace user | The **`surveytrace`** user **must** be able to read **`surveytrace.env`** so **`surveytrace-credential-check-worker`**, **`daemon/cred_decrypt_cli.php`**, and the **CLI helper** can load the key. |
| Web → helper | The API uses a **narrow sudo** invocation (no shell): **`www-data`** runs **`sudo -n -u surveytrace -- <detected PHP CLI> /opt/surveytrace/daemon/cred_secret_ops_cli.php`**, with JSON on **stdin** only. **Secrets are never passed on argv.** |
| PHP-FPM / Apache | Pools **do not** need **`SURVEYTRACE_CRED_SECRET_KEY`** exported for **`set_secret`**, **`clear_secret`**, **`action=test`**, or **`encryption.available`** when sudoers + helper are configured. Mis-injecting the key into **`php-fpm`** is unnecessary and widens exposure. |
| Helper env | **`daemon/cred_secret_ops_cli.php`** loads only an **allowlisted** subset of **`SURVEYTRACE_*`** keys from the env file (not the whole file’s namespace). |
| Helper output | Responses are **status**, **safe envelopes**, and **handshake test results** — not plaintext secrets, raw key material, or unconstrained stderr/stack traces. |
| **`SURVEYTRACE_PHP_CLI_BIN`** | **`setup.sh` / `deploy.sh`** detect the PHP CLI and write this into **`surveytrace.env`**; **`/etc/sudoers.d/surveytrace-credential-secret-helper`** must allow **exactly** the same binary path as in sudoers (single fixed command line). |

**Validation (on the installed host):**

```bash
sudo visudo -cf /etc/sudoers.d/surveytrace-credential-secret-helper
```

```bash
sudo -u www-data test -r /etc/surveytrace/surveytrace.env && echo BAD || echo OK
sudo -u surveytrace test -r /etc/surveytrace/surveytrace.env && echo SURVEYTRACE_CAN_READ || echo SURVEYTRACE_CANNOT_READ
```

```bash
PHPBIN=$(sudo grep '^SURVEYTRACE_PHP_CLI_BIN=' /etc/surveytrace/surveytrace.env | cut -d= -f2-)
sudo -u www-data sudo -n -u surveytrace -- "$PHPBIN" /opt/surveytrace/daemon/cred_secret_ops_cli.php <<'JSON'
{"action":"status"}
JSON
```

**Expected:** `visudo` reports no errors; the **`www-data`** read probe prints **`OK`** (not **`BAD`**); the **`surveytrace`** probe prints **`SURVEYTRACE_CAN_READ`**; helper JSON includes **`available": true`** and **`key_loaded": true`** (field names as returned by the helper status payload). **`GET /api/credential_profiles.php`** should show **`encryption.available": true`** when the helper path is healthy.

**Automated read-only audit:** Run **`php /opt/surveytrace/scripts/security_runtime_audit.php --install-root=/opt/surveytrace`** (as root on the server) for a consolidated PASS/WARN/FAIL report covering permissions, sudoers, helper status, manifest completeness, systemd expectations, and related checks. Exit **0** if there are no FAIL lines (WARN allowed unless you pass **`--strict`**). This script performs **no** writes, cleanup, or network probes.

**Stale shipped files after upgrades:** Renames under **`api/`**, **`daemon/`**, or **`scripts/`** can leave old paths on disk. From a fresh **`git pull`**: **`sudo bash deploy.sh --cleanup-stale`** (dry-run), review the list, then **`sudo bash deploy.sh --cleanup-stale --apply`**. The cleanup tool **never** targets **`data/`**, **`backups/`**, env files (**`.env`**, **`surveytrace.env`**), SQLite **WAL/SHM**, **`venv/`**, or log trees — see [Deployment — stale file cleanup](deployment.md#optional-stale-application-file-cleanup).

---

## Worker substrate (System health — Background jobs preview)

The **Background jobs (preview)** block on **System health** is a read-only view of the SQLite **worker execution substrate** (`worker_jobs`, `worker_nodes`, `worker_heartbeats`, `worker_job_events`). It does **not** drive scanner, collector ingest, or scheduler behavior on its own — legacy queues remain authoritative until future adapters adopt the substrate.

| UI / API signal | Meaning |
|-----------------|--------|
| Status **Unavailable** | Migration `migration_worker_execution_substrate_v1` not applied or tables missing — expected on older DBs until the app runs migrations. |
| Status **OK** (one quiet line) | Substrate is present and idle, or counts are healthy vs built-in thresholds. |
| Status **Warning** / **Error** | Actionable backlog or liveness issues (stale node heartbeats, failed/retrying jobs, old queued/running ages, recent error-level events). |

**What to do:** Open **System health → Needs attention** for merged hints. Inspect `worker_job_events` and job rows in SQLite only if you are diagnosing a future or lab feature — production ingest and scans still use their legacy tables and queues.

**Lease expiry vs collector scans:** Collector scan leases are **explicitly expired** and jobs re-queued when `lease_expires_at` passes (`api/collector_jobs.php`). The generic **`worker_jobs`** substrate stores `lease_expires_at` for observability, but **there is no automatic sweep** that moves `leased` or stuck `running` rows back to `queued` if a worker process dies mid-job. Symptom: rows stay `leased` / `running`, cred runs stay “active”, and **System health** may warn on old running ages. Mitigation today: restart the worker service, and if needed manually reconcile SQLite (cancel run from UI, or update terminal `worker_jobs` / linked `credential_check_runs` with care). **Retention:** `worker_job_events` and `worker_job_attempts` grow without pruning — plan archival or periodic delete for high-churn deployments.

Design reference: [Worker execution MVP plan](../WORKER_EXECUTION_MVP_PLAN.md) · [Worker execution substrate](../WORKER_EXECUTION_SUBSTRATE.md).

**Collector ingest mirror:** Successful chunk uploads also upsert a `worker_jobs` row (`job_type = collector_ingest`, `entity_type = collector_submission`, `entity_id = collector_submissions.id`) and append `worker_job_events`. The ingest **worker** and **submit** path update this mirror best-effort. **`collector_ingest_queue` and existing ingest/scan tables remain authoritative** — the worker substrate is a **read-only mirror for visibility**, not a second queue to drain. If mirror writes fail, collector ingest still proceeds; use **System health** collector ingest counts, `collector_ingest_queue`, and **Scan history** for operations. Retention / pruning of old mirror rows and events is not automated yet.

**Credentialed check runs:** Launching a run inserts `worker_jobs` with `job_type = credentialed_check` and `entity_id = credential_check_runs.id`. The **`surveytrace-credential-check-worker`** service (or `daemon/credential_check_worker.py` under the app venv) **must be running** for runs to leave `queued`. The worker executes **`ssh.linux.os_release@1.0.0`** (bounded **`/etc/os-release`** over SSH — **asset IP only**) and **`ssh.linux.package_inventory@1.0.0`** when selected on **SSH** profiles (fixed **`dpkg-query`** / **`rpm -qa`** only), and **`snmpv3.device_identity@1.0.0`** on **SNMPv3** profiles (three fixed GETs: sysDescr / sysObjectID / sysName — **no walk or SET**). Mismatched plugins get **`unsupported_transport`** result rows instead of failing the whole target. Requires **`php`** on PATH for **`daemon/cred_decrypt_cli.php`** when profiles store **`secret_ciphertext`**, **`SURVEYTRACE_CRED_SECRET_KEY`** aligned with the web app, **`python3`** with **`paramiko`** (SSH) and **`pysnmp`** (SNMP execution + handshake). **`SURVEYTRACE_CRED_CHECK_PLACEHOLDER_ONLY=1`** forces no remote SNMP/SSH (smoke/CI). If runs stay queued, verify `systemctl status surveytrace-credential-check-worker` and `journalctl -u surveytrace-credential-check-worker -n 50`. Cancelling uses `cancel_requested_at` plus `st_worker_finalize_queued_cancel` / leased cancel helpers so work does not stall.

**Partial / truncated package inventory:** A result row may be **`partial`** (timeout, parse loss, or policy cap) and/or carry **`truncated`** in normalized JSON when output or list size hit caps. The **host modal** and **run detail** show **counts and flags only** — not the full package list — so operators can see signal without loading megabytes in the browser. Use **run detail → normalized preview** (bounded) and DB/artifact paths for deep inspection.

**Software inventory summary (trusted-data reconciliation):** Host Details surfaces **`software_inventory_summary`** plus **`software_inventory_stale`** / **`software_inventory_partial`** hints, **`software_inventory_stale_band`** (**`fresh` \| `90_180` \| `over_180`** — reporting freshness, **not** CVSS), **`software_inventory_observation_gap`** when **`package_inventory_observed`** exists without normalized inventory corroboration (no active **`software_inventory_asset_state`** rows and no **`software_inventory_snapshot_observed`** summary — still credentialed evidence, **not** a vulnerability verdict), and a **View software evidence** disclosure. That disclosure shows bounded samples and catalog row counts — **not** the full installed package list and **not** CVE analysis; SurveyTrace does **not** generate findings from package inventory in this path. **System Health → Trusted data** lists **numeric readiness counters only** (stale splits **90–180d** vs **>180d**, repeat partial inventories, summaries lacking snapshot/normalized corroboration, etc.) — never raw package dumps; open hosts / rerun inventory when counts indicate drift. Admin **`/api/recon_diagnostics.php`** returns read-only **`software_inventory`** diagnostics per asset (no remote execution). Future scanner/API/SBOM/agent fusion is **planned reconciliation-side only** — not shipped as production authority yet.

**Authenticated evidence vs scan:** Reconciliation observations from source **`credentialed_check`** are labeled **Auth** in evidence tables (coarse tier). They **do not** bypass reconciliation: they add **medium/high-trust signal** for OS/identity reconciliation keys per [Trusted data model](../TRUSTED_DATA_MODEL.md). **Scan**-sourced rows remain **unauthenticated** context.

**Retention:** `credential_check_results` and `credential_check_artifacts` accumulate with history. There is **no automatic prune** in current releases — treat growth as operational (backup, export, manual cleanup) until a dedicated retention job ships.

**Secrets/key mismatch after restore or node move:** If credentialed runs suddenly fail with `decrypt_failed` or `encryption_unavailable`, confirm `SURVEYTRACE_CRED_SECRET_KEY` is present and identical on both PHP/web and `surveytrace-credential-check-worker` environments. Restoring DB without the original key keeps profile metadata but makes stored secrets undecryptable; operators must re-enter profile secrets.

**Rewrap after envelope hardening:** After upgrading to builds that add context metadata (`ctxh`) for secret envelopes, run `php /opt/surveytrace/scripts/rewrap_credential_secrets.php` from the install root context (dry-run first, then `--apply`) to modernize legacy rows. If rewrap reports `decrypt_failed`, keep the row unchanged and verify key parity before retrying.

**Operational history growth:** For `worker_job_events`, `worker_job_attempts`, `credential_check_results`, `credential_check_artifacts`, and `reconciliation_runs`, use `php /opt/surveytrace/scripts/prune_operational_history.php` in dry-run mode first, then `--apply` during maintenance windows. Use `--include-runs` only when you intend to prune old terminal run/job trees.

**Stuck worker substrate rows:** If `worker_jobs` or credentialed runs stay in `running` / `leased` / `retrying` after worker failure, use `php /opt/surveytrace/scripts/recover_stale_worker_jobs.php` in dry-run first, then `--apply` with `--run-sync` to align stuck run states. Prefer `--older-than-minutes=60` (or higher in slow environments). This tool marks stale rows terminal; it does not retry remote execution automatically.

**Which maintenance tool should I use?** Installed copies live under **`/opt/surveytrace/scripts/`** (same relative names from the repo).

- **Rewrap candidates present** (legacy secret envelopes): `/opt/surveytrace/scripts/rewrap_credential_secrets.php`
- **DB growth pressure from operational history**: `/opt/surveytrace/scripts/prune_operational_history.php`
- **Stuck leased/running worker state after crash/reboot**: `/opt/surveytrace/scripts/recover_stale_worker_jobs.php`

Always run dry-run first and back up before any `--apply`.

**Stale application files after upgrades:** Renamed scripts or removed **`api/`** / **`daemon/`** paths can remain under **`/opt/surveytrace`** because deploy only copies forward. Use **`sudo bash deploy.sh --cleanup-stale`** (dry-run) from a fresh **`git pull`**, inspect the list, then **`--apply`** — see [Deployment updates — stale files](deployment.md#optional-stale-application-file-cleanup). This cleans **shipped tree** leftovers only; it does **not** prune SQLite operational history (use **`prune_operational_history.php`** for that).

**Backup/restore readiness validation:** Run `php /opt/surveytrace/scripts/validate_backup_restore_readiness.php` after restore and before starting normal operations. Any `FAIL` means restore prerequisites are not satisfied; resolve before resuming credentialed checks.

**Key-loss warning (restore):** If DB restore succeeds but `SURVEYTRACE_CRED_SECRET_KEY` is missing or changed, profile metadata remains but decrypt of stored secrets fails. Re-enter profile secrets or restore the original key material.

**Multi-node warning:** Web/API and worker nodes must use the same `SURVEYTRACE_CRED_SECRET_KEY`; mismatch causes credentialed-check decrypt failures even when UI/profile metadata appears healthy.

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

**systemd sandbox:** If logs show `sqlite3.OperationalError: unable to open database file` (or similar) despite correct ownership on `data/`, the installed unit may be missing **`ReadWritePaths`** for the SurveyTrace data directory under **`ProtectSystem=strict`**. Compare `systemctl cat surveytrace-collector-ingest.service` to the repo unit template; re-run **`deploy.sh`** / refresh units from the current tree. **`setup.sh`** and **`deploy.sh`** post-checks assert this path when available.

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