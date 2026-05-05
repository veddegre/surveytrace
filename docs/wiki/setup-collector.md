# Setup Collector Node

[← Back to Documentation](README.md)

## When to use this

- Use this page when adding or rebuilding a remote collector node.
- Collectors are optional and used for distributed scanning.

## How to do it

### What the collector actually does

- Polls the master for assigned scan work.
- Runs scans from the collector network vantage point.
- Uploads artifacts/results back to the master for processing/enrichment/reporting.
- Does not replace the master UI/API/database role.

### Full setup steps

1. On the collector host:
   - `git clone <your-repo-url> surveytrace`
   - `cd surveytrace`
2. Run collector setup:
   - `cd collector`
   - `sudo ./setup.sh`
3. Open collector config:
   - `/etc/surveytrace/collector.json`
4. Set required fields:
   - master base URL
   - install token
   - collector name/site identity fields
5. Start/restart collector service after config update:
   - `sudo systemctl restart surveytrace-collector`
6. Confirm collector is visible from master collector views.

### Service startup

- Setup installs and enables the collector unit.
- Runtime should start automatically unless validation blocks startup.

## What to expect

- Collector-specific files/services are installed and validated.
- Service user permissions are enforced for runtime paths.
- Collector polls master for work and uploads results back.

### Verification

1. Collector service status:
   - `systemctl status surveytrace-collector`
2. Collector logs:
   - `journalctl -u surveytrace-collector -n 100`
3. Check registration/heartbeat from master UI.
4. Run an assigned test scan and confirm result ingestion on master.

## Common issues

- **Collector not visible on master**
  - Check base URL/install token in collector config.
- **Collector service failing**
  - Check `systemctl status surveytrace-collector`.
- **Permission/readability failures**
  - Re-run collector setup/deploy to normalize modes/ownership.
- **No jobs assigned**
  - Validate collector assignment/ranges on master scheduling side.

---

See also:
- [Documentation home](README.md)

---
