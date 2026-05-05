# Setup Collector Node

[← Back to Documentation](README.md)

## Collector role

- A collector is an optional remote scan worker.
- It runs scans close to remote networks and submits results to the master.

## How to run collector setup

- From repository root:
  - `cd collector`
  - `sudo ./setup.sh`

## Service user expectations

- Collector runtime uses the collector service account model (typically `surveytrace` on collector hosts).
- Files and config are permissioned for service runtime, not world-readable.

## Validation checks

- Collector setup runs collector-specific validation.
- Checks include:
  - required collector files and directories
  - service unit/config presence
  - ownership/mode expectations
  - service-user readability/executability

## How collectors connect to master

- Collector config points to the master base URL and uses install-token-based registration.
- The collector polls for work, executes assigned scans, and uploads results back to the master.

---

See also:
- [Documentation home](README.md)

---
