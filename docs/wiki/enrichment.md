# Enrichment

## What enrichment is

- Enrichment adds context to discovered assets after or alongside scan processing.
- It helps operators map technical scan output to operational identity and ownership signals.

## Zabbix integration

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

- **Connected**
  - Configured and enabled, with healthy recent sync state.
- **Degraded**
  - Configured but stale or warning-like sync condition.
- **Error**
  - Last sync/output failed or returned an error condition.
- **Not configured**
  - Zabbix integration is not configured or not enabled.
