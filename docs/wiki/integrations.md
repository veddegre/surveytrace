# Integrations

[← Back to Documentation](README.md)

## When to use this

- Use this page when configuring or operating Zabbix integration.
- For deeper scope-model behavior, refer to `concepts.md`.

## How to do it

1. Open **Integrations** and configure Zabbix connector values.
2. Enable sync and run **Sync now**.
3. Open **Enrichment** and review match suggestions.
4. Apply validated matches.
5. If output is needed, enable output settings and verify sender prerequisites.
6. Check status in Enrichment/System Health.

## What to expect

- Sync updates cached host/monitoring context.
- Match review requires explicit operator actions.
- Output uses `zabbix_sender` and reports last push result separately.
- Status meanings:
  - **Connected**: healthy recent sync state
  - **Degraded**: stale/warning condition
  - **Error**: last sync/output failed
  - **Not configured**: connector disabled/incomplete

## Common issues

- **Status remains Not configured**
  - Missing API URL/token or connector still disabled.
- **Status is Degraded**
  - Sync interval/freshness stale; run sync and re-check.
- **Status is Error**
  - Last sync/output failed; review error summary.
- **Output not working**
  - `zabbix_sender` missing or sender target/host settings invalid.

---

See also:
- [Documentation home](README.md)

---
