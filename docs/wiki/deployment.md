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

To allow admins to **store encrypted SSH / SNMPv3 / WinRM secrets** on credential profiles (Settings → Credentialed checks — profiles), set **`SURVEYTRACE_CRED_SECRET_KEY`** in the **PHP/web server environment** (same pattern as other SurveyTrace env vars: e.g. systemd `Environment=` on the unit that runs PHP-FPM or Apache, or your reverse-proxy–passed config — not inside SQLite).

- **Format:** trimmed string. Best: `openssl rand -base64 32` (32 raw bytes as base64). Also accepted: 64 hex chars (32 bytes), or any string (implementation derives a 32-byte key with SHA-256 — weaker if short/predictable).
- **If unset:** profile metadata CRUD still works; `set_secret` fails with **Credential encryption is not configured.**
- **Backups / restore:** the SQLite database holds **ciphertext only**. Restoring a backup on a host **without the same key** makes existing profile secrets **unusable** until operators set a new key and re-enter secrets. **Key rotation** (re-encrypt all rows with a new key) is **not** automated in the current product slice.
- **Execution:** credentialed check **worker** runs (slices 7–9) decrypt profile secrets on the worker for **`ssh.linux.os_release`**, **`ssh.linux.package_inventory`**, and **`snmpv3.device_identity`** when the profile transport matches (SNMP uses **`pysnmp`**; SSH uses **`paramiko`**). Other plugins remain placeholders. **Slice 5** still uses stored secrets for the **handshake test** subprocess from the API path.

### Credentialed checks — transport handshake test (slice 5)

After **slice 4** encryption and **slice 5** code deploy, admins can run **SSH** or **SNMPv3** handshake tests from **Settings → Credentialed checks — profiles** (modal: target host/IP, optional port).

- **Python:** the web PHP process invokes `venv/bin/python3` (or `python3`) on `daemon/cred_transport_cli.py`. Requires **`paramiko`** (SSH) and **`pysnmp`** (SNMPv3) in the same venv as the scanner (`setup.sh` installs both).
- **`proc_open`:** must not be disabled for the PHP-FPM pool user (`disable_functions` in `php.ini`).
- **SSH host keys:** default policy accepts unknown host keys for the test only (**MITM risk** on untrusted networks). Stricter: set **`SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY=reject`** (or `strict` / `no`) in the PHP environment so **paramiko** uses **RejectPolicy** (operators must align server-known_hosts or pinning separately — productized TOFU deferred).
- **Concurrency:** only one handshake test at a time per SurveyTrace data directory (file lock); a second request returns **429** with a safe message.

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