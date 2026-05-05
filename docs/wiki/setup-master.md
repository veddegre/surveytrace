# Setup Master Node

[← Back to Documentation](README.md)

## How to run setup

- From the repository root:
  - `sudo ./setup.sh`
- Choose full server/master when prompted.

## What setup installs

- Application files under `/opt/surveytrace`
- Required runtime dependencies
- System services (scanner, scheduler, ingest)
- Initial database and data directories

## Permissions model

- `surveytrace` runs daemon/scheduler workers.
- `www-data` serves web/API access.
- API and data paths are permissioned so scheduler and web access can coexist safely.

## Validation behavior

- Setup runs post-install validation checks.
- Checks include required files, directories, modes, ownership, and service/unit presence.
- Critical failures stop setup; warnings are shown for non-blocking issues.

## Common issues

- **Service not active**
  - Check `systemctl status` for the specific unit.
- **Permission/readability errors**
  - Re-run setup or deploy to normalize ownership/modes.
- **Missing optional tools**
  - `zabbix_sender` is warning-only unless output features are actively used.

---

See also:
- [Documentation home](README.md)

---
