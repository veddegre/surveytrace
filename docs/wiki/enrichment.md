# Enrichment

[← Back to Documentation](README.md)

## When to use this

- Use this page when you need to:
  - sync external system data (Zabbix)
  - link SurveyTrace assets to monitored systems
  - verify monitoring status and availability
  - troubleshoot enrichment health or stale data

---

## How to do it

### Full enrichment workflow

1. Configure Zabbix integration (API + connection).
2. Run initial sync.
3. Review match candidates.
4. Apply confirmed matches.
5. Verify asset updates.

---

### How to run sync

1. Open **Enrichment → Zabbix** section.
2. Confirm status shows:
   - configured
   - enabled
3. Click **Run sync now**.
4. Wait for:
   - last sync time to update
   - status to refresh

Optional manual sync:

```bash
sudo -u surveytrace php /opt/surveytrace/api/zabbix_sync_worker.php
```

---

### How to use Zabbix match review

1. Click **Open tools** in the Zabbix section.
2. Review candidate matches:
   - IP-based matches
   - hostname matches
   - confidence score
3. Validate carefully:
   - confirm asset ↔ host alignment
4. Apply:
   - single matches (recommended)
   - or scoped rule if consistent pattern

5. Re-check assets:
   - open asset details
   - confirm monitoring status is applied

---

### How to verify enrichment worked

After applying matches:

1. Go to **Assets**
2. Open a matched asset
3. Confirm:
   - monitored status is set
   - availability is shown (available/unavailable)
   - Zabbix context is visible

---

## What to expect

- Sync pulls Zabbix host data into SurveyTrace.
- Match review does **not auto-link assets** — it requires operator confirmation.
- After linking:
  - assets show monitoring state
  - availability becomes visible
- Status indicators reflect:
  - sync health
  - output state (separate)

---

## How enrichment works (important)

- Sync imports Zabbix hosts → stored in internal cache
- Match review links:
  - SurveyTrace asset → Zabbix host
- After linking:
  - asset fields are updated (denormalized)
- Future syncs:
  - refresh availability/status automatically

---

## Common issues

### Status shows Not configured

- Zabbix API settings are missing or incomplete
- Fix:
  - go to **Integrations → Zabbix**
  - enter API URL and token

---

### Status shows Degraded

- Sync has not run recently
- Fix:
  - click **Run sync now**
  - check scheduler is running:

```bash
systemctl status surveytrace-scheduler
```

---

### Status shows Error

- Last sync or output failed

Check logs:

```bash
journalctl -u surveytrace-scheduler -n 50
```

Common causes:
- API auth failure
- network issue
- invalid endpoint

---

### Zabbix availability shows "unknown"

Possible causes:
- sync has not run
- availability fields not returned by API
- asset not matched yet

Fix:
1. Run sync
2. Confirm match exists
3. Re-open asset

---

### No matches found

- No overlapping identifiers (IP/hostname)
- Sync may not have completed

Fix:
- verify Zabbix hosts exist
- run sync again
- confirm IP alignment

---

### Matches look incorrect

- Auto-matching is heuristic (IP/hostname)

Fix:
- review before applying
- use manual matching where needed

---

### Data looks stale

- Scheduler not running or delayed

Check:

```bash
systemctl status surveytrace-scheduler
```

- Verify last sync time in UI

---

## Status meanings (quick reference)

- **Connected**
  - Sync is recent and successful
  - Integration is healthy

- **Degraded**
  - Sync is stale or partially successful

- **Error**
  - Last sync/output failed

- **Not configured**
  - Integration is not set up

---

## Operational tips

- Run sync after initial setup and after API changes
- Do not bulk-apply low-confidence matches
- Validate a few assets manually before scaling
- Monitor System Health → Zabbix regularly

---

See also:
- [API Keys](api-keys.md)
- [Integrations](integrations.md)
- [Getting Started](getting-started.md)
- [Documentation home](README.md)