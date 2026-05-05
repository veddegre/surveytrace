# Reporting

[← Back to Documentation](README.md)

## When to use this

- Use this page when you need to:
  - review scan results over time
  - understand current asset risk posture
  - compare environments or scopes
  - troubleshoot “missing” report data

- For deeper scope behavior, see [Concepts](concepts.md)

---

## How to do it

### Step-by-step reporting usage

1. Open **Reports & Analysis**
2. Select a **scope filter**
3. Choose reporting mode:
   - **Job scope** → historical scan results
   - **Inventory scope** → current asset state
4. Review report sections/cards
5. If data is missing:
   - verify scope
   - verify mode
   - verify scans exist

---

### How to choose job vs inventory scope

Use this quick decision guide:

- Use **Job scope** when:
  - analyzing trends
  - comparing scans
  - reviewing drift over time
  - validating past scan results

- Use **Inventory scope** when:
  - checking current risk
  - counting assets/findings
  - reviewing environment state
  - answering “what exists now?”

If unsure:
- run both modes and compare outputs

---

## What to expect

### Job scope mode

- Based on **completed scan jobs**
- Includes:
  - trends
  - comparisons
  - baselines
  - drift analysis

Important:
- requires **completed scan jobs**
- does NOT use enrichment-only data

---

### Inventory scope mode

- Based on **current asset inventory**
- Includes:
  - asset counts
  - open findings
  - severity breakdown
  - lifecycle/state grouping

Important:
- reflects **current state**
- includes enrichment updates

---

### Key difference

| Mode            | Data source       | Use case                  |
|-----------------|------------------|---------------------------|
| Job scope       | scan_jobs        | historical analysis       |
| Inventory scope | assets           | current state visibility  |

---

## Why reports may show no data

This is the most common issue.

### Scenario

- Scope selected (e.g., "Vedorama")
- Assets exist in **Assets view**
- Reports appear empty

### Root cause

- Assets are assigned to scope (**inventory scope**)
- But no scan jobs were run with that scope (**job scope**)

---

### Result

- Job scope reports → empty
- Inventory scope reports → populated

---

## How to fix missing data

### Fix 1 — Run a scoped scan

- Go to **Scan control**
- Select the correct scope
- Run scan
- Wait for completion

---

### Fix 2 — Switch reporting mode

- Change to **Inventory scope**
- View current state instead of historical data

---

## Common issues

### No data in job scope

- No completed scans for that scope

Check:

```bash
sqlite3 /opt/surveytrace/data/surveytrace.db "SELECT id, scope_id, status FROM scan_jobs ORDER BY id DESC LIMIT 10;"
```

---

### No data in inventory scope

- Assets not assigned to that scope

Fix:
- verify scope assignment in Assets
- update asset scope if needed

---

### Results differ between modes

- This is expected behavior
- One shows **history**, the other shows **current state**

---

### Reports appear broken

Usually caused by:
- wrong scope selected
- wrong mode selected
- misunderstanding of job vs inventory model

---

### Inventory-only data expected in job mode

- Not supported
- Job mode only uses completed scan data

Fix:
- run a scan
- or switch to inventory mode

---

### Data looks stale

Possible causes:
- no recent scans
- scheduler not running

Check:

```bash
systemctl status surveytrace-scheduler
```

---

## Operational tips

- Always run at least one scan per scope you plan to report on
- Use inventory mode for quick checks
- Use job mode for audits and comparisons
- Re-run scans regularly to keep reports relevant

---

## Quick mode choice

- Use **Job scope** → “What did scans show over time?”
- Use **Inventory scope** → “What is true right now?”

---

## Quick validation checklist

- scope selected correctly
- correct mode selected
- scans completed (for job mode)
- assets exist (for inventory mode)
- scheduler running
- no errors in logs

---

See also:
- [Concepts](concepts.md)
- [Scanning](scanning.md)
- [Getting Started](getting-started.md)
- [Documentation home](README.md)