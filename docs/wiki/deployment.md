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

- copy updated files to `/opt/surveytrace`
- normalize ownership and permissions
- validate required files exist
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