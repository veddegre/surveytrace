# Integrations

[← Back to Documentation](README.md)

## Zabbix integration overview

- Zabbix integration supports:
  - sync of host/monitoring context into SurveyTrace
  - match review workflows for linking data to assets
  - optional output back to Zabbix via `zabbix_sender`

## Sync

- Sync pulls Zabbix data into SurveyTrace cache tables.
- Run manually from Enrichment/Integrations or use scheduled sync if enabled.
- Freshness/state is updated after sync attempts.

## Match review

- Use Enrichment match review tools to inspect and apply mappings.
- Apply operations are explicit operator actions, not silent background changes.

## Output (`zabbix_sender`)

- Output is optional and separate from sync.
- Requires `zabbix_sender` on Debian/Ubuntu when output is enabled.
- Output status includes last push time/result when configured.

## Status meanings

- **Connected**
  - Configured and enabled with healthy recent sync state.
- **Degraded**
  - Configured but stale/warning condition.
- **Error**
  - Last sync or output failed.
- **Not configured**
  - Connector not configured or disabled.

## Where configuration lives

- Integrations tab (Zabbix connector settings)
- Enrichment tab (operational review/match workflows)
- System Health (integration status visibility)

---

See also:
- [Documentation home](README.md)

---
