# Integrations

[← Back to Documentation](README.md)

## When to use this

- Use this page when configuring or operating Zabbix integration.
- For deeper scope-model behavior, refer to `concepts.md`.

## How to do it

### Zabbix setup (step-by-step)

1. Open **Settings/Integrations** and configure Zabbix API URL and token.
2. Test connection.
3. Run first sync.
4. Open **Enrichment** tab.
5. Run match review.
6. Apply validated matches.

### How matching works

1. Sync imports Zabbix hosts and interfaces.
2. Matching uses host/network identity signals (including IP context).
3. Review suggested links before apply.
4. Apply can be manual override when auto suggestion is not desired.

## What to expect

- Sync updates cached host/monitoring context.
- Match review requires explicit operator actions.
- Output uses `zabbix_sender` and reports last push result separately.
- Status meanings:
  - **Connected**: healthy recent sync state
  - **Degraded**: stale/warning condition
  - **Error**: last sync/output failed
  - **Not configured**: connector disabled/incomplete

### Availability/status

- Availability labels:
  - `available`
  - `unavailable`
  - `unknown`
- Derived from synced Zabbix availability fields; can remain `unknown` if source has no usable availability state.
- Linked asset denorm follows the matched host status values.

### Output (`zabbix_sender`)

- What it does:
  - pushes SurveyTrace summary metrics to Zabbix.
- Requirements:
  - sender binary present
  - output target configured
  - connector enabled with valid auth/config
- How to verify:
  1. Trigger output/test path.
  2. Check last output status/time in UI health/integration views.
  3. Validate destination receives expected keys.

## Common issues

- **Status remains Not configured**
  - Missing API URL/token or connector still disabled.
- **Status is Degraded**
  - Sync interval/freshness stale; run sync and re-check.
- **Status is Error**
  - Last sync/output failed; review error summary.
- **Output not working**
  - `zabbix_sender` missing or sender target/host settings invalid.
- **Matches are missing**
  - Run sync first and verify host/interface data exists before review.

---

See also:
- [Documentation home](README.md)

---
