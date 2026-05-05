# Deployment Updates

[← Back to Documentation](README.md)

## When to use this

- Use this page for routine updates to an existing install.
- For first install, use setup docs instead.

## How to do it

1. Pull the latest code to the target host.
2. Run `sudo ./deploy.sh` from repository root.
3. Wait for file sync, permission normalization, and service restart.
4. Review post-deploy validation output.
5. Confirm health/status in the UI.

## What to expect

- Updated files copied into install path.
- Expected services restarted for current node role.
- Validation checks run for files, permissions, and service/unit readiness.

## Common issues

- **Deploy check fails on mode/owner**
  - Re-run deploy; verify expected permission policy.
- **Service restart fails**
  - Review `systemctl status` and related journal output.
- **UI shows stale behavior**
  - Confirm deploy ran on the correct host and version file updated.
- **Collector/master mismatch**
  - Use role-appropriate setup/deploy path on each node type.

---

See also:
- [Documentation home](README.md)

---
