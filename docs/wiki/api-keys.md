# API Keys

[← Back to Documentation](README.md)

## When to use this

- Use this page when adding, rotating, or troubleshooting external service credentials.

## How to do it

1. Identify which feature requires a key (AI provider, integration, feed).
2. Add/update the key in the matching Settings/Integrations section.
3. Save configuration.
4. Run the related test/sync action if available.
5. Confirm status changes to healthy/connected.

## What to expect

- Features depending on the key become active after save/test.
- Invalid keys usually surface as connection/auth errors in status messages.
- Rotated keys require updating stored config before old key expiry.

## Common issues

- **Auth failed after key update**
  - Key may be malformed, expired, or missing required scope.
- **Feature still disabled**
  - Verify key was saved in correct section and service can reach endpoint.
- **Unexpected key exposure risk**
  - Remove keys from scripts/repos and rotate immediately.
- **Rotation caused outage**
  - Stage new key, validate, then revoke old key.

---

See also:
- [Documentation home](README.md)

---
