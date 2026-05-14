# Setup Master Node

[← Back to Documentation](README.md)

## When to use this

- Use this page for:
  - first-time master installation
  - rebuilding a master node
  - validating a broken installation

- Do **not** use this for routine updates  
  → use [Deployment updates](deployment.md)

---

## How to do it

### 1. Clone the repository

```bash
git clone <your-repo-url> surveytrace
cd surveytrace
```

---

### 2. Run setup

```bash
sudo ./setup.sh
```

- Select **full server / master** when prompted.

---

### 3. Allow setup to complete

The script performs:

- package/runtime installation (PHP includes **`php-xml`** for **XMLReader** and **`php-bz2`** for **`.xml.bz2`** OVAL streams — Ubuntu **`--fetch`** / weekly advisory sync; plus the operational integrity selftests that **`deploy.sh`** runs)
- service user creation (`surveytrace`)
- application deployment to `/opt/surveytrace`
- database initialization
- permission normalization
- systemd unit install + enable + start
- post-install validation

---

## What `setup.sh` actually does

- Creates required user/group model:
  - `surveytrace`
  - `www-data` group sharing
- Installs core runtime:
  - scheduler
  - scanner daemon
  - ingest components
- Sets permissions:
  - API readable by services
  - data writable only where required
- Creates database:
  - `/opt/surveytrace/data/surveytrace.db`
- Enables services:
  - auto-start on boot
- Runs validation:
  - fails on critical issues
  - warns on optional components

---

## What to expect

After a successful install:

- Files exist under `/opt/surveytrace`
- Services are installed and running
- Database is initialized
- Web UI is accessible
- Validation passes or shows only warnings

---

## Post-install verification (required)

### Check scheduler

```bash
systemctl status surveytrace-scheduler
```

---

### Check scanner daemon

```bash
systemctl status surveytrace-daemon
```

---

### Check ingest worker

```bash
systemctl status surveytrace-collector-ingest
```

---

### Confirm services enabled

```bash
systemctl is-enabled surveytrace-scheduler surveytrace-daemon surveytrace-collector-ingest
```

Expected:
- all return `enabled`

---

### Verify database

```bash
ls -l /opt/surveytrace/data/surveytrace.db
```

Expected:
- file exists
- correct ownership
- writable by service

---

### Open web UI

```text
http://<server-ip>/
```

Confirm:
- UI loads
- no API errors

---

### Check logs

```bash
journalctl -u surveytrace-scheduler -n 50
```

---

## File structure

- `/opt/surveytrace/api`
  - PHP API + worker scripts

- `/opt/surveytrace/public`
  - Web UI entrypoint

- `/opt/surveytrace/data`
  - SQLite DB, runtime state, locks

- `/opt/surveytrace/daemon`
  - Python scheduler and scan workers

---

## Permissions model

### Users

- `surveytrace`
  - runs scheduler and workers

- `www-data`
  - serves web/API layer

---

### Why permissions matter

- scheduler must execute PHP workers
- web must read API files
- database must be writable by runtime only

---

### Common failure patterns

- API unreadable → scheduler jobs fail silently
- data not writable → scans fail or DB errors
- wrong ownership → services run but do nothing

---

## Common issues

### Service not running after setup

Check:

```bash
systemctl status surveytrace-scheduler surveytrace-daemon
```

---

### Permission validation failed

Fix:

```bash
sudo ./setup.sh
```

or

```bash
sudo ./deploy.sh
```

---

### Database not writable

Check:

```bash
ls -ld /opt/surveytrace/data
```

Ensure:
- owned by correct user/group
- writable by runtime

---

### Web UI loads but nothing works

Likely causes:
- scheduler not running
- permissions broken

Check:

```bash
journalctl -u surveytrace-scheduler -n 50
```

---

### zabbix_sender warning

- Only required if using Zabbix output
- Install if needed:

```bash
sudo apt install zabbix-sender
```

---

## Operational tips

- Always verify services immediately after setup
- Run a test scan to confirm full pipeline
- Do not manually modify `/opt/surveytrace` permissions
- Use deploy script for updates, not setup

---

## Quick validation checklist

- setup completed without errors
- services are running
- database exists
- UI loads
- logs show no critical errors
- first scan can be started

---

See also:
- [Getting Started](getting-started.md)
- [Collector setup](setup-collector.md)
- [Deployment updates](deployment.md)
- [Documentation home](README.md)