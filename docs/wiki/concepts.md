# Concepts

[← Back to Documentation](README.md)

## When to use this

- Use this page when:
  - reports don’t show expected data
  - scope behavior is confusing
  - understanding how SurveyTrace stores and separates data

---

## Scan jobs (historical snapshots)

- A scan job is a single execution of a scan.
- Each job produces a **point-in-time snapshot** of:
  - discovered assets
  - open ports
  - findings

### Key behavior

- Jobs are **immutable** after completion.
- They do not change even if:
  - assets are enriched later
  - vulnerabilities are updated
- Each job represents **exactly what was known at that time**.

### When to use scan jobs

- Comparing changes over time
- Auditing past state
- Reporting on “what did we know then?”

---

## Inventory (current state)

- Inventory represents the **latest known state** of all assets.

- It is continuously updated by:
  - scan results
  - enrichment (Zabbix, AI, etc.)

### What inventory contains

- current asset attributes
- latest findings
- enrichment data
- classifications and tags

### Key behavior

- Inventory is **mutable**
- It reflects **current truth**, not historical truth

### When to use inventory

- Understanding current environment
- Operational decision-making
- Asset grouping and filtering

---

## How scan jobs and inventory relate

- Scan jobs **feed** inventory.

Flow:

```text
scan → job results → asset updates → inventory
```

- Inventory is built from the **latest known data**
- Scan jobs are **never overwritten**

---

## Job scope vs Inventory scope

### Job scope

- Applied to a scan job at runtime
- Stored with the job itself

Used for:

- historical reports
- drift comparisons
- job-based analysis

---

### Inventory scope

- Applied to assets (current state)
- Independent of scan job history

Used for:

- grouping assets
- filtering inventory
- inventory-based reporting

---

## What to expect

- A scope can exist in **inventory only** (no scans yet)
- A scope can exist in **job history only** (older scans)
- These are intentionally independent

---

## Why reports may show no data

This is the most common confusion.

### Scenario

- You select a scope (e.g., "Vedorama")
- You see assets in **Assets**
- But reports show nothing

### Why this happens

- Assets belong to that scope (**inventory scope**)
- But no scan jobs were run with that scope (**job scope**)

### Result

- **Job scope reports** → empty
- **Inventory scope reports** → populated

---

## How to fix “no data” issues

### Option 1 — Run a scoped scan

- Start a scan using the intended scope
- This creates job history for that scope

### Option 2 — Switch report mode

- Use **Inventory scope mode** in Reports
- This shows current asset data instead of job history

---

## Common misunderstandings

### “Assets exist, so reports should have data”

- Not true
- Assets come from inventory
- Reports may require job history

---

### “Enrichment should populate reports”

- Not directly
- Enrichment updates inventory
- Job-based reports still require completed scans

---

### “Scopes are global”

- They are not
- Job scope and inventory scope are separate by design

---

## Design intent

SurveyTrace separates:

- **Historical truth (scan jobs)**
- **Current truth (inventory)**

This allows:

- accurate comparisons over time
- stable audit history
- flexible current-state reporting

---

## Quick reference

| Concept         | Purpose                  | Changes over time |
|-----------------|--------------------------|------------------|
| Scan job        | Historical snapshot      | No               |
| Inventory       | Current asset state      | Yes              |
| Job scope       | Scope of scan job        | No               |
| Inventory scope | Scope of current assets  | Yes              |

---

See also:
- [Reporting](reporting.md)
- [Getting Started](getting-started.md)
- [Documentation home](README.md)