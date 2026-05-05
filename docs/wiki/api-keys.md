# API Keys

[← Back to Documentation](README.md)

## When to use this

- Use this page when adding, rotating, or troubleshooting external service credentials.

## How to do it

1. Identify which system needs credentials (NVD, Zabbix API, AI provider).
2. Enter/update key/token in the relevant Settings/Integrations form.
3. Save settings.
4. Run test/sync action for that integration.
5. Confirm status updates in UI health/integration indicators.

## What to expect

- Features depending on the key become active after save/test.
- Invalid keys usually surface as connection/auth errors in status messages.
- Rotated keys require updating stored config before old key expiry.

### NVD (critical)

- Why it matters:
  - NVD provides CVE feed data used for vulnerability correlation.
- How to get key:
  - request from NVD API key portal (NIST).
- Where to configure:
  - Settings -> NVD/API key section (or supported environment variable path if used operationally).
- How to verify:
  1. Trigger sync from UI or run feed worker flow.
  2. Check sync status/last result in UI.
  3. Confirm no auth/rate-limit errors in logs.

### Zabbix API

- Required permissions:
  - read access for host/sync-relevant API methods.
- URL format:
  - API endpoint must include correct Zabbix API path (not just base host).
- Token/user setup:
  - create API token/user with minimum required read scope.
- Common mistakes:
  - wrong URL path
  - expired/revoked token
  - insufficient API permissions

### AI provider (optional)

- Local vs remote:
  - local runtime (for local model deployment) vs remote hosted provider API.
- Configuration:
  - provider selection + key/token/base URL fields in settings.
- Verification:
  1. Save provider/key settings.
  2. Run an AI-backed action (summary/explain path).
  3. Confirm response and no auth/runtime errors.

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
