# Enrichment

[← Back to Documentation](README.md)

## When to use this

- Use this page when you need to sync Zabbix data, review matches, and confirm enrichment health.

## How to do it

1. Open **Enrichment** and go to the Zabbix section.
2. Check top status and last sync indicator.
3. Click **Run sync now** when data is stale or missing.
4. Open **Match review** tools.
5. Review suggested links and scope actions.
6. Apply only validated matches.
7. Confirm updated host context in **Assets/Host details**.

## What to expect

- Sync refreshes cached Zabbix host/monitoring context.
- Match review shows candidates and lets you apply explicit changes.
- Status should move toward **Connected** after successful sync.
- Optional output push state is separate from sync state.

## Common issues

- **Status stays Not configured**
  - Connector settings are incomplete or disabled.
- **Status shows Degraded**
  - Sync is stale; run sync and verify schedule.
- **Status shows Error**
  - Last sync/output failed; inspect message in health/integrations.
- **Zabbix availability remains unknown**
  - Sync may not have imported availability fields yet; run sync again and verify mapping.
- **Matches look wrong**
  - Review manually before applying; do not bulk-apply uncertain rows.

## Status meanings (quick reference)

- **Connected**
  - Configured and enabled, with healthy recent sync state.
- **Degraded**
  - Configured but stale or warning-like sync condition.
- **Error**
  - Last sync/output failed or returned an error condition.
- **Not configured**
  - Zabbix integration is not configured or not enabled.

---

See also:
- [Documentation home](README.md)

---
