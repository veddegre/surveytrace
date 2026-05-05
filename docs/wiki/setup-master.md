# Setup Master Node

[← Back to Documentation](README.md)

## When to use this

- Use this page for first-time master installation or master rebuild.
- Do not use this for routine updates; use deployment workflow instead.

## How to do it

### Full installation walkthrough

1. Clone the repository on the target host:
   - `git clone <your-repo-url> surveytrace`
   - `cd surveytrace`
2. Run master setup:
   - `sudo ./setup.sh`
3. Choose full server/master when prompted.
4. Let setup complete all stages:
   - package/runtime install
   - service account creation (`surveytrace`)
   - app copy into `/opt/surveytrace`
   - database bootstrap in `/opt/surveytrace/data`
   - permission normalization for scheduler/web access
   - systemd unit install/enable/start
   - post-install validation checks

### What `setup.sh` does

- Creates/ensures required service user/group model.
- Installs and configures core services (scanner/scheduler/ingest paths).
- Sets ownership/modes for API/public/data/daemon paths.
- Creates initial DB/data structure.
- Enables scheduler and related runtime services.

## What to expect

- Master files install under `/opt/surveytrace`.
- Core services are installed/enabled (scanner, scheduler, ingest).
- Permissions are normalized for `surveytrace` and `www-data`.
- Validation checks fail on critical issues and warn on optional ones.

### Post-install verification

Run these checks after setup:

1. Scheduler status:
   - `systemctl status surveytrace-scheduler`
2. Scanner status:
   - `systemctl status surveytrace-daemon`
3. Ingest worker status:
   - `systemctl status surveytrace-collector-ingest`
4. Service enablement:
   - `systemctl is-enabled surveytrace-scheduler surveytrace-daemon surveytrace-collector-ingest`
5. Database exists:
   - `ls -l /opt/surveytrace/data/surveytrace.db`
6. Web UI loads:
   - open `http://<server-ip>/` in browser

### File structure explanation

- `/opt/surveytrace/api`
  - PHP API endpoints and CLI PHP workers.
- `/opt/surveytrace/public`
  - Web UI entrypoint and static assets.
- `/opt/surveytrace/data`
  - Runtime databases, locks, and operational state.
- `/opt/surveytrace/daemon`
  - Python worker/scheduler/scanner runtime scripts.

### Permissions model

- `surveytrace`
  - Owns/executes daemon and scheduler runtime paths.
- `www-data`
  - Reads web/API content and participates in shared group access where required.
- Why this matters:
  - scheduler PHP workers must be readable by `surveytrace`
  - web/API paths must be readable by `www-data`
  - data paths must be writable by runtime services only
- Common failure modes:
  - wrong API mode/owner -> scheduler worker read failures
  - wrong data mode/owner -> DB write/open failures
  - service user mismatch -> units run but tasks fail

## Common issues

- **Service not active after setup**
  - Check `systemctl status surveytrace-daemon surveytrace-scheduler`.
- **Permission check failed**
  - Re-run setup/deploy to re-apply owner/group/mode policy.
- **Database or data path not writable**
  - Verify `surveytrace`/`www-data` access under `/opt/surveytrace/data`.
- **zabbix_sender warning**
  - Install `zabbix-sender` only if you plan to use output push.

---

See also:
- [Documentation home](README.md)

---
