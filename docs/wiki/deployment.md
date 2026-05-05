# Deployment Updates

[← Back to Documentation](README.md)

## How to run deploy

- From the repository root:
  - `sudo ./deploy.sh`

## What deploy updates

- Syncs updated application/runtime files to the install path.
- Refreshes expected permissions and ownership where applicable.
- Restarts expected services for the node role.

## Validation checks

- Deploy runs post-deploy validation checks.
- Checks include required paths/files, read/execute access, and unit presence.
- Critical issues fail the deploy; warnings are printed for non-blocking conditions.

## Deploy vs setup

- Use **setup** for first-time installation.
- Use **deploy** for updates to an existing installation.

## Safe update workflow

- Pull latest code on the target host.
- Run `sudo ./deploy.sh`.
- Confirm service status and health indicators in the UI.
- If needed, review system logs for failed units or permission errors.

---

See also:
- [Documentation home](README.md)

---
