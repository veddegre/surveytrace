# Integrations

[← Back to Documentation](README.md)

## When to use this

- Use this page when:
  - configuring Zabbix integration for the first time
  - troubleshooting sync, matching, or output issues
  - validating integration health and status

- For deeper data-model behavior, see [Concepts](concepts.md)

---

## How to do it

### Zabbix setup (step-by-step)

1. Open **Settings → Integrations → Zabbix**
2. Enter:
   - API URL (must include `/api_jsonrpc.php`)
   - API token or credentials
3. Click **Test connection**
4. Save configuration
5. Run first sync:
   - click **Run sync now**
6. Open **Enrichment**
7. Open **match review tools**
8. Review and apply matches
9. Verify assets are enriched

---

### Example API URL

```text
https://<zabbix-host>/api_jsonrpc.php
```

---

### How matching works

1. Sync imports:
   - Zabbix hosts
   - interfaces
   - availability fields

2. Matching uses:
   - IP address (primary)
   - hostname (secondary)
   - other identity hints

3. System generates:
   - candidate matches
   - confidence values

4. Operator must:
   - review matches
   - confirm correctness
   - apply selected matches

---

### Manual match guidance

- Use **manual override** when:
  - IPs differ (NAT, proxies, containers)
  - hostnames do not match
- Avoid:
  - bulk applying low-confidence matches

---

## What to expect

- Sync populates internal Zabbix cache
- Match review does **not auto-link assets**
- After applying matches:
  - assets show monitoring state
  - availability becomes visible
- Output push is independent of sync

---

## Availability and status

### Availability labels

- `available` → host reachable
- `unavailable` → host monitored but not reachable
- `unknown` → no usable availability data

---

### How availability is derived

- From Zabbix API fields:
  - host-level availability
  - interface-level availability
- If no valid fields are returned:
  - status remains `unknown`

---

### Asset behavior

- Once matched:
  - asset inherits Zabbix availability
  - updates occur during sync
- No match = no availability data

---

## Output (`zabbix_sender`)

### What it does

- Sends SurveyTrace metrics back to Zabbix

Examples:
- asset counts
- risk summaries
- environment metrics

---

### Requirements

- `zabbix_sender` installed on system
- correct target host configured
- integration enabled

---

### How to verify

1. Trigger output (manual or scheduled)

2. Check UI:
   - last output time
   - last output status

3. Check logs:

```bash
journalctl -u surveytrace-scheduler -n 50
```

4. Validate in Zabbix:
   - expected items updated
   - no sender errors

---

## Status meanings

- **Connected**
  - recent successful sync
  - integration healthy

- **Degraded**
  - sync is stale or partial

- **Error**
  - last sync or output failed

- **Not configured**
  - integration missing or disabled

---

## Common issues

### Status remains Not configured

- Missing API URL or token
- Integration not saved or enabled

---

### Status is Degraded

- Sync not running automatically
- Scheduler may not be active

Check:

```bash
systemctl status surveytrace-scheduler
```

---

### Status is Error

- API failure or auth issue

Check:

```bash
journalctl -u surveytrace-scheduler -n 50
```

---

### Output not working

- `zabbix_sender` not installed

Check:

```bash
which zabbix_sender
```

- invalid target configuration
- incorrect host/item mapping

---

### Matches are missing

- Sync not run
- No overlapping IP/hostname

Fix:
- run sync
- verify Zabbix hosts exist

---

### Availability shows unknown

- No availability fields returned from API
- Host not monitored in Zabbix
- Asset not matched

---

## Operational tips

- Always run sync after changing API settings
- Validate a few matches before bulk apply
- Monitor System Health → Zabbix regularly
- Keep Zabbix API permissions minimal (read-only)

---

## Quick validation checklist

- API test passes
- Sync completes successfully
- Hosts appear in Enrichment
- Matches can be reviewed
- Assets show availability after linking
- Status shows **Connected**

---

See also:
- [API Keys](api-keys.md)
- [Enrichment](enrichment.md)
- [Concepts](concepts.md)
- [Documentation home](README.md)