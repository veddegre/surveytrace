# Scanning

[← Back to Documentation](README.md)

## When to use this

- Use this page when you need to:
  - run new scans
  - monitor scan execution
  - review scan results
  - troubleshoot scan behavior

---

## How to do it

### Start a scan

1. Open **Scan control**
2. Select:
   - scan profile
   - scan options (if available)
3. Enter target:
   - single IP (e.g., `192.168.1.10`)
   - CIDR range (e.g., `192.168.1.0/24`)
4. Click **Start scan**

---

### Monitor scan progress

1. Open **Scan history**
2. Watch job state transition:
   - queued → running → completed
3. Click a job to view details:
   - duration
   - status
   - output summary

---

### Review results

After completion:

- Open **Assets**
- Open **Host details** for specific systems
- Review:
  - open ports
  - detected services
  - findings
  - classifications

---

### Re-run a scan

- From **Scan history**:
  - select a previous job
  - click re-run (or repeat with same settings)

Use this for:
- validation
- comparison
- drift analysis

---

## What to expect

- A scan creates a **new job record**
- Jobs move through states:
  - queued → running → done / failed / aborted
- Completed jobs:
  - are **immutable snapshots**
  - do not change after completion
- Assets:
  - are created or updated from scan results
- Results appear in:
  - Scan history
  - Assets
  - Host details

---

## Scan states (quick reference)

- **queued**
  - waiting for execution
- **running**
  - actively scanning targets
- **done**
  - completed successfully
- **failed**
  - error during execution
- **aborted**
  - manually or system stopped

---

## How scanning works (under the hood)

- Scan job is created
- Scheduler assigns work
- Scanner daemon executes scan
- Results are processed
- Assets are updated
- Findings are stored

---

## Common issues

### Scan stays queued

Check:

```bash
systemctl status surveytrace-scheduler
```

Possible causes:
- scheduler not running
- scanner daemon not active
- resource constraints

---

### Scan fails immediately

Possible causes:
- invalid target (bad CIDR or hostname)
- network unreachable
- permission issues

Check logs:

```bash
journalctl -u surveytrace-scheduler -n 50
```

---

### Scan runs but finds nothing

Possible causes:
- no live hosts in range
- firewall blocking probes
- scan profile too restrictive

---

### No new assets after completion

Possible causes:
- results filtered in UI
- scan did not discover hosts
- assets already existed and were updated silently

---

### Scan takes too long

Possible causes:
- large CIDR range
- slow network
- limited system resources

---

## Operational tips

- Start with small ranges to validate setup
- Expand scan scope gradually
- Re-run scans periodically to maintain current data
- Use scan history for comparison and auditing

---

## Quick validation checklist

- scan appears in history
- job progresses from queued → running → done
- no errors in logs
- assets appear or update
- results visible in UI

---

## Related commands

```bash
# check scheduler
systemctl status surveytrace-scheduler

# view logs
journalctl -u surveytrace-scheduler -n 50
```

---

See also:
- [Reporting](reporting.md)
- [Concepts](concepts.md)
- [Getting Started](getting-started.md)
- [Troubleshooting — Collector results and master ingest](troubleshooting.md#collector-results-and-master-ingest) — when jobs use collector nodes and the master shows submission/ingest states
- [Documentation home](README.md)