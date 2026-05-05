# Setup Master Node

[← Back to Documentation](README.md)

## When to use this

- Use this page for first-time master installation or master rebuild.
- Do not use this for routine updates; use deployment workflow instead.

## How to do it

1. From repository root, run `sudo ./setup.sh`.
2. Choose full server/master when prompted.
3. Wait for package install, file copy, service setup, and permission steps.
4. Review post-install validation output.
5. Confirm services are active and UI is reachable.

## What to expect

- Master files install under `/opt/surveytrace`.
- Core services are installed/enabled (scanner, scheduler, ingest).
- Permissions are normalized for `surveytrace` and `www-data`.
- Validation checks fail on critical issues and warn on optional ones.

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
