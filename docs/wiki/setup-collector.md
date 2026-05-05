# Setup Collector Node

[← Back to Documentation](README.md)

## When to use this

- Use this page when adding or rebuilding a remote collector node.
- Collectors are optional and used for distributed scanning.

## How to do it

1. On the collector host, go to repository root.
2. Run:
   - `cd collector`
   - `sudo ./setup.sh`
3. Configure collector connection values (master URL/install token).
4. Start/confirm collector service.
5. Verify collector appears online on the master.

## What to expect

- Collector-specific files/services are installed and validated.
- Service user permissions are enforced for runtime paths.
- Collector polls master for work and uploads results back.

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
