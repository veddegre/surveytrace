# API Keys

[← Back to Documentation](README.md)

## When to use this

- Use this page when:
  - configuring SurveyTrace integrations for the first time
  - rotating credentials
  - troubleshooting failed integrations (NVD, Zabbix, AI)

---

## How to do it

1. Identify the integration:
   - NVD (vulnerability data)
   - Zabbix (enrichment + monitoring)
   - AI provider (optional summaries)

2. Open **Settings** or **Integrations** in the UI.

3. Enter required credentials:
   - API key, token, or endpoint URL

4. Save configuration.

5. Run a validation action:
   - **Test connection**
   - **Run sync**
   - **Trigger AI action**

6. Verify results:
   - UI status indicators (Connected / Degraded / Error)
   - System Health → Integrations
   - Logs if needed

---

## What to expect

- Features tied to the integration become active immediately after a successful save/test.
- Failed credentials will result in:
  - connection errors
  - authentication failures
  - “unknown” or stale data in UI
- Some integrations (like Zabbix) require an additional sync step before data appears.
- Rotating a key without updating SurveyTrace will break the integration.

---

## NVD (critical)

### Why it matters

- Provides CVE data used for:
  - vulnerability correlation
  - severity scoring (CVSS)

---

### How to get a key

- Request from NVD (NIST) API portal:

  https://nvd.nist.gov/developers/request-an-api-key

---

### How to verify

1. Trigger sync via UI **or** run manually:

```bash
sudo -u surveytrace php /opt/surveytrace/api/nvd_sync_worker.php
```

2. Check logs:

```bash
journalctl -u surveytrace-scheduler -n 50
```

---

## Zabbix API

### How to verify

1. Run sync:

```bash
sudo -u surveytrace php /opt/surveytrace/api/zabbix_sync_worker.php
```

2. Check UI:
   - Enrichment tab shows hosts
   - Status is no longer "unknown"

---

## Common issues

### Zabbix shows "unknown"

- Sync not run
- API not returning availability fields

### NVD has no data

- API key missing or invalid
- Sync never executed

---

See also:
- [Integrations](integrations.md)
- [Documentation home](README.md)