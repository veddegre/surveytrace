# Enrichment

[← Back to Documentation](README.md)

## When to use this

- Use this page when you need to sync Zabbix data, review matches, and confirm enrichment health.

## How to do it

### Full enrichment workflow

1. Configure integration settings (Zabbix/API requirements).
2. Run sync.
3. Review matches.
4. Apply validated matches.
5. Verify asset updates in Assets/Host details.

### How to run sync

1. Open Enrichment Zabbix section.
2. Confirm connector status is configured/enabled.
3. Click **Run sync now**.
4. Wait for last sync/result indicators to refresh.

### How to use Zabbix match review

1. Open match review tools.
2. Inspect candidate link rows and scope suggestions.
3. Apply only high-confidence or manually confirmed mappings.
4. Re-check affected assets after apply.

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
- **No matches found**
  - Sync may have no overlapping identifiers yet (run sync and verify host data).
- **Data looks stale**
  - Last sync may be old; run sync and check scheduler health.

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
