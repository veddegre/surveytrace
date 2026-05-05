# Setup Collector Node

[← Back to Documentation](README.md)

## When to use this

- Use this page when:
  - adding a new collector node
  - rebuilding an existing collector
  - troubleshooting collector connectivity or scan execution
- Collectors are optional and used for **distributed scanning**.

---

## What the collector actually does

- Polls the master for assigned scan jobs
- Executes scans from its local network vantage point
- Uploads results back to the master for:
  - asset updates
  - enrichment
  - reporting
- Does **not**:
  - host the UI
  - store primary data
  - replace the master node

---

## How to do it

### 1. Clone repository on collector host

```bash
git clone <your-repo-url> surveytrace
cd surveytrace
```

---

### 2. Run collector setup

```bash
cd collector
sudo ./setup.sh
```

This will:

- create collector service (`surveytrace-collector`)
- install runtime files
- create configuration file
- validate permissions and environment

---

### 3. Configure collector

Edit:

```text
/etc/surveytrace/collector.json
```

Required fields:

- `master_url` — base URL of SurveyTrace master
- `install_token` — token generated from master
- `collector_name` — unique identifier
- optional:
  - site/location metadata

---

### 4. Start or restart collector service

```bash
sudo systemctl restart surveytrace-collector
```

---

### 5. Confirm registration

- Open master UI
- Navigate to collector or scan control view
- Confirm collector appears and is reachable

---

## Service behavior

- Collector service:
  - runs continuously
  - polls master for work
- If idle:
  - no scans are executed
- When work is assigned:
  - collector runs scan
  - uploads results automatically

---

## Verification

### Check collector service

```bash
systemctl status surveytrace-collector
```

Expected:

- active (running)
- no repeated failures

---

### Check logs

```bash
journalctl -u surveytrace-collector -n 100
```

Look for:

- successful registration
- polling activity
- job execution messages

---

### Confirm from master

- collector appears in UI
- collector is eligible for scan assignment

---

### Test scan

1. Assign a scan to collector
2. Run scan
3. Confirm:
   - job executes on collector
   - results appear in master UI

---

## What to expect

- Collector installs minimal runtime components
- No database or UI is installed
- All results are processed on the master
- Collector acts only as execution node

---

## Common issues

### Collector not visible on master

Possible causes:

- incorrect `master_url`
- invalid or missing `install_token`

Fix:

- verify config file
- restart collector service

---

### Collector service failing

Check:

```bash
systemctl status surveytrace-collector
journalctl -u surveytrace-collector -n 100
```

Common causes:

- configuration errors
- permission issues
- missing dependencies

---

### Permission or readability errors

- collector cannot access required paths

Fix:

```bash
cd collector
sudo ./setup.sh
```

---

### No jobs assigned

Possible causes:

- no scan targets mapped to collector
- scheduling configuration on master not including collector

Fix:

- verify scan assignment rules on master
- confirm collector is eligible for selected targets

---

### Jobs assigned but not executed

Possible causes:

- collector not polling successfully
- connectivity issue to master

Check:

```bash
journalctl -u surveytrace-collector -n 100
```

---

## Operational tips

- Give collectors meaningful names (site/location)
- Use collectors for:
  - segmented networks
  - remote sites
  - bandwidth-sensitive environments
- Monitor collector health regularly via logs and UI

---

## Quick validation checklist

- collector service running
- collector appears in master UI
- collector receives jobs
- scans execute successfully
- results appear in master

---

See also:
- [Installation (Master)](setup-master.md)
- [Scanning](scanning.md)
- [Deployment updates](deployment.md)
- [Documentation home](README.md)