# Deployment Updates

[← Back to Documentation](README.md)

## When to use this

- Use this page for **routine updates** to an existing SurveyTrace installation.
- Use after:
  - pulling new code
  - upgrading to a new version
  - applying fixes or patches
- For first-time install, use **setup-master.md** instead.

---

## How to do it

### 1. Pull latest code

```bash
git pull
```

---

### 2. Run deploy

```bash
sudo ./deploy.sh
```

This must be run from the **repository root directory**.

---

### 3. Wait for deployment to complete

The deploy script will:

- copy updated files to `/opt/surveytrace` (including explicit `api/*.php`, `daemon/` modules, `public/`, `sql/schema.sql`, and **`docs/`** operator reference)
- normalize ownership and permissions
- validate required files exist (including trusted-data / reconciliation PHP and `recon_observations.py` where shipped)
- run targeted `php -l` / `python3 -m py_compile` checks when configured in the script
- check worker readability
- verify systemd units
- restart services as needed

---

### 4. Review validation output

Pay attention to:

- ❌ failures (must fix)
- ⚠ warnings (should review)

Deployment should **not be considered successful** if failures are reported.

---

### 5. Verify system after deploy

#### Check scheduler

```bash
systemctl status surveytrace-scheduler
```

Expected:
- active (running)
- no repeated errors

---

#### Check web UI

Open:

```text
http://<server-ip>/
```

Confirm:
- UI loads normally
- no missing data or API errors

---

#### Check logs

```bash
journalctl -u surveytrace-scheduler -n 50
```

Look for:
- errors
- failed workers
- repeated retries

---

## What to expect

After a successful deploy:

- application code is updated
- services are restarted cleanly
- database remains intact
- configuration is preserved
- UI reflects new version (check VERSION file or UI indicator)

---

## Credentialed checks — profile secret encryption (optional)

To allow admins to **store encrypted SSH / SNMPv3 credential secrets** on credential profiles (Settings → Credentialed checks — profiles), set **`SURVEYTRACE_CRED_SECRET_KEY`** in the **PHP/web server environment** (same pattern as other SurveyTrace env vars: e.g. systemd `Environment=` on the unit that runs PHP-FPM or Apache, or your reverse-proxy–passed config — not inside SQLite).

- **Format:** trimmed string. Best: `openssl rand -base64 32` (32 raw bytes as base64). Also accepted: 64 hex chars (32 bytes), or any string (implementation derives a 32-byte key with SHA-256 — weaker if short/predictable).
- **Strict mode (recommended):** set `SURVEYTRACE_CRED_SECRET_KEY_STRICT=1` to require only strong key formats (base64-32-byte or 64-hex). In strict mode, short passphrases are rejected.
- **If unset:** profile metadata CRUD still works; `set_secret` fails with **Credential encryption is not configured.**
- **Multi-node requirement:** every process that decrypts profile secrets (web/PHP path and `surveytrace-credential-check-worker`) must have the **same** `SURVEYTRACE_CRED_SECRET_KEY` value.
- **Backups / restore:** back up SQLite and key material together. Restoring DB data on a host **without the same key** makes existing profile secrets **unusable** until operators set a new key and re-enter secrets.
- **Key rotation:** bulk re-wrap/rotation is **not** automated in the current product slice.
- **Execution:** credentialed check **worker** runs (slices 7–9) decrypt profile secrets on the worker for **`ssh.linux.os_release`**, **`ssh.linux.package_inventory`**, and **`snmpv3.device_identity`** when the profile transport matches (SNMP uses **`pysnmp`**; SSH uses **`paramiko`**). Other plugins remain placeholders. **Slice 5** still uses stored secrets for the **handshake test** subprocess from the API path.

### Manual secret rewrap utility (slice 1)

Use `scripts/rewrap_credential_secrets.php` when you need to modernize stored envelopes (for example, after enabling ctxh-compatible releases or tightening key policy):

```bash
# Dry-run (default): counts only
php scripts/rewrap_credential_secrets.php

# Apply changes
php scripts/rewrap_credential_secrets.php --apply

# Single profile
php scripts/rewrap_credential_secrets.php --apply --profile-id=123
```

- Rewrap is **manual only** (no background daemon).
- Do **not** run rewrap after changing the key unless the old key is still available for decrypt.
- If decrypt fails for a row, the row remains unchanged and the utility reports a safe failure code.

### Manual operational prune utility (slice 2)

Use `scripts/prune_operational_history.php` to prune old operational history tables. Run dry-run first:

```bash
# Dry-run (default)
php scripts/prune_operational_history.php --older-than-days=90

# Apply conservative prune
php scripts/prune_operational_history.php --older-than-days=90 --apply

# Include old terminal run/job trees (still manual)
php scripts/prune_operational_history.php --older-than-days=90 --apply --include-runs
```

Recommended first run:

1. Backup DB.
2. Dry-run with `--older-than-days=120` (or `90` for higher churn).
3. Review counts.
4. Apply during a maintenance window.

Notes:

- No automatic pruning daemon exists in this release.
- Tool is intentionally conservative and avoids active/running/queued/retrying rows.
- `--vacuum` is explicit; consider WAL/write-lock impact before running VACUUM.
- Maintenance scripts under `scripts/` are **not deployed by `deploy.sh`** by default; run them from a repo/maintenance workspace.

### Manual stale worker recovery utility (slice 3)

Use `scripts/recover_stale_worker_jobs.php` to recover stale worker substrate rows after crashes/reboots:

```bash
# Dry-run
php scripts/recover_stale_worker_jobs.php --older-than-minutes=60 --run-sync

# Apply safe default (credentialed_check only, mark stale jobs failed)
php scripts/recover_stale_worker_jobs.php --older-than-minutes=60 --run-sync --apply
```

Notes:

- Start with dry-run and back up the DB before `--apply`.
- Tool does not retry remote execution automatically.
- Default excludes `collector_ingest` recovery; include explicitly with `--job-type=collector_ingest` or `all` only if you intend to touch that substrate.

## Routine maintenance runbook (operator quick path)

Run monthly (or before release promotion), in this order:

1. Backup DB (`daemon/backup_db.sh` or your standard backup flow).
2. `php scripts/rewrap_credential_secrets.php` (dry-run)
3. `php scripts/prune_operational_history.php --older-than-days=90` (dry-run)
4. `php scripts/recover_stale_worker_jobs.php --older-than-minutes=60 --run-sync` (dry-run)
5. Apply only if needed, during a maintenance window.

Why this is manual in current releases:

- No automatic prune scheduler.
- No automatic stale-recovery sweeper.
- Operator review remains the safety boundary before state-changing maintenance.

## Backup / restore validation (slice 5)

This release line adds a read-only backup/restore readiness validator:

- `php scripts/validate_backup_restore_readiness.php`

It checks DB readability, schema presence, encrypted profile counts, key availability/decrypt viability, operational table counts, and maintenance script presence. It never prints plaintext secrets and does not mutate DB state.

### Backup set requirements

Before upgrades or maintenance windows, back up:

1. `data/surveytrace.db` (and active `-wal` / `-shm` sidecars when present).
2. Environment/config file containing `SURVEYTRACE_CRED_SECRET_KEY` (for example `/etc/surveytrace/surveytrace.env`).
3. Systemd environment wiring/overrides used in your deployment.
4. Any local custom docs/config outside git.

### Restore order (recommended)

1. Stop SurveyTrace services.
2. Restore DB + env/config files together.
3. Verify `SURVEYTRACE_CRED_SECRET_KEY` is present and identical to backup-era key.
4. Run `php scripts/validate_backup_restore_readiness.php`.
5. Start services.
6. Validate System Health and credentialed-check run status.

Important:

- Restoring DB without the original key breaks decrypt for stored credential profile secrets.
- Multi-node deployments must keep key parity across web/API and worker nodes.

### Recommended EnvironmentFile pattern

For systemd-managed deployments, keep runtime secrets in a root-owned env file and reference it from all relevant services:

```ini
# /etc/surveytrace/surveytrace.env
SURVEYTRACE_CRED_SECRET_KEY=<generated-random-key>
SURVEYTRACE_CRED_SECRET_KEY_STRICT=1
```

- Set permissions to `root:root` and mode `0600`.
- Add `EnvironmentFile=/etc/surveytrace/surveytrace.env` to the units that run PHP and the credential-check worker (or equivalent override files), then restart those services.
- Validate with one handshake test from Settings and one small credentialed run before declaring production-ready.

### Credentialed checks — transport handshake test (slice 5)

After **slice 4** encryption and **slice 5** code deploy, admins can run **SSH** or **SNMPv3** handshake tests from **Settings → Credentialed checks — profiles** (modal: target host/IP, optional port).

- **Python:** the web PHP process invokes `venv/bin/python3` (or `python3`) on `daemon/cred_transport_cli.py`. Requires **`paramiko`** (SSH) and **`pysnmp`** (SNMPv3) in the same venv as the scanner (`setup.sh` installs both).
- **Worker decrypt dependency:** worker hosts also need **`php`** on PATH for `daemon/cred_decrypt_cli.php` when encrypted profile secrets are used.
- **`proc_open`:** must not be disabled for the PHP-FPM pool user (`disable_functions` in `php.ini`).
- **SSH host keys:** default policy accepts unknown host keys for the test only (**MITM risk** on untrusted networks). Stricter: set **`SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY=reject`** (or `strict` / `no`) in the PHP environment so **paramiko** uses **RejectPolicy** (operators must align server-known_hosts or pinning separately — productized TOFU deferred).
- **Concurrency:** only one handshake test at a time per SurveyTrace data directory (file lock); a second request returns **429** with a safe message.

---

## External secret stores (current state)

SurveyTrace currently uses app-managed envelope encryption (`secret_ciphertext` + `SURVEYTRACE_CRED_SECRET_KEY`).

- No HashiCorp Vault integration yet.
- No cloud KMS integration yet.
- No automatic key rotation/re-wrap workflow yet.

Treat these as explicit non-goals for the current release line.

---

## Safe update workflow (recommended)

For production environments:

1. Pull code
2. Review changes (optional but recommended)
3. Run deploy:
   ```bash
   sudo ./deploy.sh
   ```
4. Validate:
   - services
   - UI
   - integrations
5. Monitor logs for a few minutes

---

## Common issues

### Deploy check fails on permissions or ownership

- Cause:
  - files manually modified
  - incorrect ownership
- Fix:
  - re-run deploy
  - ensure correct user/group (`surveytrace:www-data`)

---

### Service restart fails

Check:

```bash
systemctl status surveytrace-scheduler
journalctl -u surveytrace-scheduler -n 50
```

Common causes:
- syntax errors in updated files
- missing dependencies
- permission issues

---

### UI shows stale behavior

Possible causes:
- deploy run on wrong host
- browser cache
- service did not restart

Fix:
- hard refresh browser
- confirm VERSION updated
- restart services manually if needed:

```bash
sudo systemctl restart surveytrace-scheduler
```

---

### Collector and master mismatch

- Cause:
  - master updated but collector not updated (or vice versa)
- Fix:
  - run `deploy.sh` on each node type separately
  - ensure versions match across nodes

---

### Validation fails for missing files

- Cause:
  - incomplete repo
  - failed pull
- Fix:
  - re-run `git pull`
  - re-run `deploy.sh`

---

## When NOT to use deploy.sh

Do NOT use deploy.sh:

- for first installation
- when system is partially installed or broken
- when permissions are severely corrupted (use setup.sh instead)

---

## Quick validation checklist

- deploy script completed without failures
- scheduler service is running
- UI loads correctly
- no errors in logs
- integrations still show **Connected**
- version updated

---

## Related commands (quick reference)

```bash
# run deploy
sudo ./deploy.sh

# check scheduler
systemctl status surveytrace-scheduler

# view logs
journalctl -u surveytrace-scheduler -n 50

# restart scheduler
sudo systemctl restart surveytrace-scheduler
```

---

See also:
- [Getting Started](getting-started.md)
- [Setup (Master)](setup-master.md)
- [Documentation home](README.md)