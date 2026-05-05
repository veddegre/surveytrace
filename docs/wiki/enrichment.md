# Enrichment

[← Back to Documentation](README.md)

## What enrichment is

- Enrichment adds context to discovered assets after or alongside scan processing.
- It helps operators map technical scan output to operational identity and ownership signals.

## Zabbix integration

### How to run sync

- Open the Enrichment or Integrations area for Zabbix.
- Run sync to refresh cached Zabbix host/monitoring context.
- Verify the last sync/result indicators after completion.

### How to use Zabbix match review

- Open Zabbix match review tools in Enrichment.
- Review suggested links/mappings.
- Apply only validated matches or scope actions you intend to keep.

### Matching assets

- Zabbix host data can be matched to SurveyTrace assets.
- Match review and workflow tools help validate and apply mappings.

### Sync behavior

- Sync pulls Zabbix host/monitoring data into SurveyTrace caches.
- Manual sync and scheduled sync both update freshness and status indicators.

### Output (`zabbix_sender`)

- Optional output pushes SurveyTrace metrics back to Zabbix.
- Requires `zabbix_sender` on Debian/Ubuntu when output is enabled.
- Output status is tracked separately from sync status.

## Status meanings

### How to interpret status

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
