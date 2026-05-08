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

- copy updated files to `/opt/surveytrace` using **`scripts/deploy_file_manifest.php`** as the single source of truth for **`api/*.php`**, shipped **`daemon/`** modules, **`scripts/*.php`** (maintenance CLIs + production selftests), **`public/`**, **`sql/`**, and **`docs/`** (full tree)
- run **`php scripts/check_deploy_coverage.php`** from the repo **before** copying (flags missing/extra files versus the manifest — avoids silent drift)
- normalize ownership and permissions
- validate required files exist (including trusted-data / reconciliation PHP and `recon_observations.py` where shipped)
- run **`php -l`** on every shipped **`api/*.php`**, **`daemon/cred_decrypt_cli.php`**, and **`scripts/*.php`** from the manifest; run **`python3 -m py_compile`** on shipped **`daemon/*.py`**
- check worker readability
- verify systemd units
- restart services as needed

**Maintenance tooling path:** operator CLIs and bundled selftests live under **`/opt/surveytrace/scripts`** after **`setup.sh`** or **`deploy.sh`**. Prefer **`--dry-run`** on maintenance scripts before **`--apply`**. Dev-only helpers (**`scripts/smoke_credential_checks_placeholder.*`**, **`scripts/verify_schedule_cron_parity.py`**) stay in the repo for CI/local use only — they are intentionally omitted from the manifest.

Do **not** deploy by blind **`cp -a *`** from a workstation tree; use **`deploy.sh`** / **`setup.sh`** so excludes and manifests stay aligned.

---

### Optional: stale application file cleanup

Renamed or retired **`api/`**, **`daemon/`**, **`scripts/`**, **`sql/`**, root **`*.service`**, or (when compared to your checkout) **`docs/`** files can linger under **`/opt/surveytrace`** because **`deploy.sh`** only overwrites — it does not erase old names. That leftover code is confusing and can be a security concern.

**This cleanup removes shipped tree cruft only.** It does **not** replace **`prune_operational_history.php`** (SQLite row pruning), **`recover_stale_worker_jobs.php`**, backup tooling, or data retention policy. Always **dry-run first**, keep backups, and treat **`--apply`** as destructive to listed paths.

From the **repo root** on the server (after `git pull`) — so the manifest and **`--repo-src`** match your checkout (recommended):

```bash
sudo bash deploy.sh --cleanup-stale
```

`--cleanup-stale` may appear in **any** position among the arguments (so wrappers can prepend flags). If you see **Deploying SurveyTrace from /opt/surveytrace to /opt/surveytrace** and `cp` errors, the **`deploy.sh` on disk is still an older copy** — run **`sudo bash ~/surveytrace/deploy.sh --cleanup-stale`** once from your **git checkout** so the updated script is used, or copy `deploy.sh` from the checkout onto `/opt/surveytrace` first.

When you invoke **`/opt/surveytrace/deploy.sh`**, that file is only as current as your **last `deploy.sh` run from a checkout** — each successful master deploy **copies** `deploy.sh` from the checkout into **`/opt/surveytrace/deploy.sh`**. Until you run **`sudo bash ./deploy.sh`** from **`~/surveytrace`** once after upgrading, **`/opt/surveytrace/deploy.sh` can be stale** (missing flags like `--cleanup-stale` handling).

With **`SRC` = `/opt/surveytrace`**, set **`SURVEYTRACE_REPO_SRC=/path/to/git/checkout`** for **`docs/`** stale detection vs a fresher tree (optional). **Syncing application files from git** means running **`deploy.sh` from the checkout** (so `SRC` is the checkout, `DEST` is `/opt/surveytrace`).

That invokes **`scripts/cleanup_deployed_stale_files.php`** with the **current repo manifest** and **`--repo-src`** set to your checkout so **`docs/`** can be compared safely. Default is **dry-run** (prints candidates only). To delete the listed files:

```bash
sudo bash deploy.sh --cleanup-stale --apply
```

Review the table carefully before **`--apply`**. Unexpected files under **`public/`** are listed separately and are **not** deleted unless you also pass **`--apply-public-extras`** (operators sometimes add static assets — default is conservative).

You can run the PHP entrypoint directly (e.g. custom **`--audit-log=`**):

```bash
sudo php /opt/surveytrace/scripts/cleanup_deployed_stale_files.php \
  --install-root=/opt/surveytrace \
  --manifest-path=/path/to/current/repo/scripts/deploy_file_manifest.php \
  --repo-src=/path/to/current/repo \
  --apply
```

Deletes are refused under **`data/`**, **`backups/`**, **`venv/`**, **`.git/`**, for **`.env`** / **`surveytrace.env`**, SQLite/WAL/SHM, and **`*.log`** basenames. **`integrations-starter/`** is not scanned. Successful **`--apply`** runs append JSON lines to **`data/deploy_stale_cleanup_audit.log`** by default (append-only).

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

## Credentialed checks — helper PHP CLI + secret encryption (optional)

SurveyTrace runs credential secret operations through a narrow sudo helper command:

- `www-data ALL=(surveytrace) NOPASSWD: <detected-php-cli> /opt/surveytrace/daemon/cred_secret_ops_cli.php`
- The PHP CLI path is detected during `setup.sh` / `deploy.sh` and persisted as `SURVEYTRACE_PHP_CLI_BIN` in `/etc/surveytrace/surveytrace.env`.
- Detection order is: existing `SURVEYTRACE_PHP_CLI_BIN` (if valid CLI binary), `command -v php`, `/usr/bin/php`, `/usr/local/bin/php`, then versioned `/usr/bin/php*` CLI candidates.
- PHP-FPM/CGI binaries are rejected for helper use; sudoers remains intentionally narrow and exact-path.
- Runtime secret permissions must be:
  - `/etc/surveytrace` -> `root:surveytrace` mode `750`
  - `/etc/surveytrace/surveytrace.env` -> `root:surveytrace` mode `640`
- `www-data` cannot read `/etc/surveytrace/surveytrace.env` directly.
- `surveytrace` can read `/etc/surveytrace/surveytrace.env`, so the helper can load the key.
- Web requests reach key operations only through the narrow sudo helper path (`www-data -> sudo -u surveytrace -> cred_secret_ops_cli.php`).

To allow admins to **store encrypted SSH / SNMPv3 credential secrets** on credential profiles (Settings → Credentialed checks — profiles), set **`SURVEYTRACE_CRED_SECRET_KEY`** in `/etc/surveytrace/surveytrace.env` (not inside SQLite).

- **Format:** trimmed string. Best: `openssl rand -base64 32` (32 raw bytes as base64). Also accepted: 64 hex chars (32 bytes), or any string (implementation derives a 32-byte key with SHA-256 — weaker if short/predictable).
- **Strict mode (recommended):** set `SURVEYTRACE_CRED_SECRET_KEY_STRICT=1` to require only strong key formats (base64-32-byte or 64-hex). In strict mode, short passphrases are rejected.
- **If unset:** profile metadata CRUD still works; `set_secret` fails with **Credential encryption is not configured.**
- **Multi-node requirement:** every component that decrypts profile secrets — **`surveytrace-credential-check-worker`** (reads `EnvironmentFile`) and **`daemon/cred_secret_ops_cli.php`** when invoked via sudo from the web pool — must use the **same** `SURVEYTRACE_CRED_SECRET_KEY` value. The php-fpm pool user must **not** need the key in its own environment for normal `set_secret` / handshake flows (those go through the helper).
- **Backups / restore:** back up SQLite and key material together. Restoring DB data on a host **without the same key** makes existing profile secrets **unusable** until operators set a new key and re-enter secrets.
- **Key rotation:** bulk re-wrap/rotation is **not** automated in the current release.
- **Execution:** credentialed check **worker** runs decrypt profile secrets on the worker for **`ssh.linux.os_release`**, **`ssh.linux.package_inventory`**, and **`snmpv3.device_identity`** when the profile transport matches (SNMP uses **`pysnmp`**; SSH uses **`paramiko`**). Other plugins remain placeholders. The **handshake test** path still uses stored secrets for its subprocess from the API layer.

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

For systemd-managed deployments, keep runtime secrets in an env file readable by `surveytrace` (not `www-data`) and reference it from all relevant services:

```ini
# /etc/surveytrace/surveytrace.env
SURVEYTRACE_CRED_SECRET_KEY=<generated-random-key>
SURVEYTRACE_CRED_SECRET_KEY_STRICT=1
```

- Set permissions to:
  - directory `/etc/surveytrace` as `root:surveytrace` mode `0750`
  - file `/etc/surveytrace/surveytrace.env` as `root:surveytrace` mode `0640`
- Add `EnvironmentFile=/etc/surveytrace/surveytrace.env` to the units that run PHP and the credential-check worker (or equivalent override files), then restart those services.
- Validate with one handshake test from Settings and one small credentialed run before declaring production-ready.

### Credentialed checks — transport handshake test (slice 5)

After **slice 4** encryption and **slice 5** code deploy, admins can run **SSH** or **SNMPv3** handshake tests from **Settings → Credentialed checks — profiles** (modal: target host/IP, optional port).

- **Python:** the web PHP process invokes `venv/bin/python3` (or `python3`) on `daemon/cred_transport_cli.py`. Requires **`paramiko`** (SSH) and **`pysnmp`** (SNMPv3) in the same venv as the scanner (`setup.sh` installs both).
- **Worker decrypt dependency:** worker hosts also need **`php`** on PATH for `daemon/cred_decrypt_cli.php` when encrypted profile secrets are used.
- **`proc_open`:** must not be disabled for the PHP-FPM pool user (`disable_functions` in `php.ini`).
- **SSH host keys:** the **Settings → handshake test** subprocess always uses **AutoAddPolicy** (unknown keys accepted; **MITM risk** on untrusted networks — documented tradeoff). **`SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY`** is **not** applied there so a pool-wide **`reject`** does not break first-connect tests. For **automated cred SSH** (`daemon/cred_check_ssh_os_release.py`, package inventory), prefer **`SURVEYTRACE_CRED_SSH_CHECK_HOST_KEY_POLICY`**: set **`accept_new`** (or `auto`, `allow`, …) on worker units when many dynamic assets must be reached without pre-seeding **`known_hosts`** (same MITM caveat). Use **`reject`** / **`strict`** / **`no`** when the key must already be trusted. If **`SURVEYTRACE_CRED_SSH_CHECK_HOST_KEY_POLICY`** is **unset**, workers still honor legacy **`SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY=reject`** for cred checks. To pin keys instead, add them under **`surveytrace`**’s home **`~/.ssh/known_hosts`** (run **`sudo -u surveytrace bash -lc '…'`** so **`$HOME`** is correct; do not rely on **`~surveytrace`** expanded from your login shell).
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

### UI says credential encryption is not configured

- Symptom:
  - UI shows `Credential encryption is not configured`
  - helper status returns `env_file_present=false` and/or `env_file_readable=false`
- Cause:
  - `/etc/surveytrace` is not traversable by `surveytrace` (wrong owner/group or mode)
  - or `/etc/surveytrace/surveytrace.env` owner/group/mode blocks `surveytrace` reads
- Fix:
  - `sudo chown root:surveytrace /etc/surveytrace && sudo chmod 750 /etc/surveytrace`
  - `sudo chown root:surveytrace /etc/surveytrace/surveytrace.env && sudo chmod 640 /etc/surveytrace/surveytrace.env`
  - verify:
    - `sudo -u www-data test -r /etc/surveytrace/surveytrace.env && echo BAD || echo OK`
    - `sudo -u surveytrace test -r /etc/surveytrace/surveytrace.env && echo SURVEYTRACE_CAN_READ || echo SURVEYTRACE_CANNOT_READ`
    - `sudo -u www-data sudo -n -u surveytrace -- <detected_php_cli> /opt/surveytrace/daemon/cred_secret_ops_cli.php <<< '{"action":"status"}'`

---

### Credential helper fails in browser but `sudo` works from SSH (`sudo_exit_code: 1`)

- Symptom:
  - `encryption.helper_available === false`, `helper_error_code` / `helper_invoke.sudo_exit_code` is `1`
  - `sudo -u www-data sudo -n -u surveytrace -- /usr/bin/php …/cred_secret_ops_cli.php` from a shell succeeds
- Cause (Ubuntu, Apache with hardened `apache2.service`):
  - `systemctl show apache2` includes **`RestrictSUIDSGID=yes`**. That blocks **setuid** executables (including **`/usr/bin/sudo`**) from processes started under the Apache unit — e.g. **`mod_php`**. CLI tests are not subject to that cgroup, so they lie.
- Fix (pick one):
  1. **Recommended:** Serve SurveyTrace PHP via **php-fpm + `proxy_fcgi`** (as in `setup.sh` Apache vhost), not **`mod_php`**. PHP then runs under **`php8.x-fpm.service`**, which does not use Apache’s `RestrictSUIDSGID` sandbox for the interpreter.
  2. **Narrow override:** `sudo systemctl edit apache2` and set `[Service]` **`RestrictSUIDSGID=no`**, then `daemon-reload` + restart Apache. Understand this weakens setuid blocking for **all** Apache children.
- Verify: `systemctl show apache2 --no-pager | grep RestrictSUIDSGID`

#### Migrating an existing host from `mod_php` to php-fpm

- On Debian/Ubuntu, run as **root**: **`sudo bash /opt/surveytrace/scripts/migrate_apache_modphp_to_phpfpm.sh`** (or from a checkout: **`sudo bash scripts/migrate_apache_modphp_to_phpfpm.sh`**). Optional **`--dry-run`**. Override install root with **`SURVEYTRACE_INSTALL_DIR`** if not **`/opt/surveytrace`**.
- The script installs **`php${VER}-fpm`**, **`libapache2-mod-proxy-fcgi`**, disables **`libapache2-mod-php*`** Apache modules, switches to **`mpm_event`**, writes **`/etc/apache2/sites-available/surveytrace.conf`**, drops **`env[SURVEYTRACE_INSTALL_DIR]`** into **`/etc/php/${VER}/fpm/pool.d/zzz-surveytrace-install-dir.conf`**, and restarts **php-fpm** + **apache2**. Backups under **`/root/surveytrace-migrate-fpm-*`**.
- **`setup.sh`** (Apache branch) uses the **same** choices: **`CGIPassAuth On`** on **`/api`** and **`public`**, **`proxy:unix:…fpm.sock`**, **`zzz-surveytrace-install-dir.conf`**, **`mpm_event`**, and disabling all **`php*.load`** modules. Greenfield installs and the migration script stay aligned; brownfield **`mod_php`** hosts should run the migration script rather than re-running the full **`setup.sh`** just for Apache.
- After migration, confirm **`sudo -l -U www-data`** still matches the credential helper (pool user is usually still **`www-data`**).

---

### `Defaults use_pty` + Apache `PrivateDevices=yes` (web sudo fails, shell `www-data` works)

- Symptom: **`sudo -l`** shows the correct **`NOPASSWD`** line; **`sudo -u www-data env -i … sudo -n …`** from SSH **succeeds**; browser / **`mod_php`** still gets **`sudo: I'm sorry www-data. I'm afraid I can't do that`** and empty helper stdout.
- Cause: **`/etc/sudoers`** often has **`Defaults use_pty`**, which makes **`sudo`** allocate a **pseudo-TTY**. **`apache2.service`** on recent Ubuntu may set **`PrivateDevices=yes`**, which **restricts `/dev`** in the worker — **PTY allocation can fail** inside that namespace, and **`sudo`** can surface a **generic policy denial** even when **`NOPASSWD`** is correct.
- Fix: **`setup.sh`** / **`deploy.sh`** write **`/etc/sudoers.d/surveytrace-credential-secret-helper`** with **`Cmnd_Alias ST_CRED_SECRET_OPS`**, **`Defaults!ST_CRED_SECRET_OPS !use_pty`** (command-scoped), **`Defaults:www-data !use_pty`** (or your real pool user from **`SURVEYTRACE_CRED_HELPER_WEB_USER`** — redundant with the command line but helps on some sudo builds), and **`NOPASSWD: ST_CRED_SECRET_OPS`**. Re-run setup/deploy as root, **`sudo visudo -cf /etc/sudoers.d/surveytrace-credential-secret-helper`**, then **`sudo systemctl restart apache2`**. Legacy **`surveytrace-credential-sudo-usepty`** is removed when you re-run setup/deploy.
- Alternative: migrate SurveyTrace to **php-fpm + `proxy_fcgi`** (recommended stack in **`setup.sh`**) and re-evaluate whether you still need the **`!use_pty`** line for **`mod_php`**.

---

### `stderr_sanitized` contains “I’m afraid I can’t do that” (sudo policy denial)

- Meaning: **sudo** refused the command for **`www-data`** (or your pool user). This is **not** encryption misconfiguration; the argv did not match an allowed **`NOPASSWD`** rule (or another **`Defaults`** rule blocked it).
- As root, list effective rules: `sudo -l -U www-data` (replace `www-data` with your php pool user).
- Open `/etc/sudoers.d/surveytrace-credential-secret-helper` and confirm **`Cmnd_Alias ST_CRED_SECRET_OPS`** lists the **same** PHP binary and script path the helper runs, then **`NOPASSWD: ST_CRED_SECRET_OPS`** (paths, no extra args).

  On Debian/Ubuntu, **`/usr/bin/php`** is often a symlink via **`/etc/alternatives`** to **`/usr/bin/php8.x`**. Sudo may validate the **resolved** path; if the web helper invokes **`/usr/bin/php8.5`** but sudoers only list **`/usr/bin/php`**, you can get a policy denial. Use the **same path** in sudoers, **`SURVEYTRACE_PHP_CLI_BIN`**, and the helper (current `setup.sh` / `deploy.sh` / `lib_cred_secret_helper.php` canonicalize to **`readlink -f` / `realpath`**).
- Check for **`Defaults requiretty`** (or similar) affecting `www-data`; non-interactive `sudo -n` from the web needs a rule that does not require a TTY for this command.
- After edits: `sudo visudo -cf /etc/sudoers.d/surveytrace-credential-secret-helper`

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