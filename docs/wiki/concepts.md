# Concepts

[← Back to Documentation](README.md)

## Scan jobs (historical snapshots)

- A scan job is a single run with its own point-in-time results.
- Completed jobs are historical records and do not automatically change later.
- Use scan jobs when you need to compare what changed across runs.

## Inventory (current state)

- Inventory is the current state of known assets and findings.
- It can be updated by scan processing and enrichment workflows.
- Inventory answers "what is true right now?"

## Job scope vs Inventory scope

- **Job scope**
  - Scope attached to a scan job.
  - Used for historical, job-based reporting.
- **Inventory scope**
  - Scope attached to current assets.
  - Used for grouping and inventory-based reporting.

## Why reports may show no data

- A scope can have assets but no completed scoped jobs.
- In that case:
  - **Job scope reports** may show little or no data.
  - **Inventory scope reports** can still show current asset/finding state.
- If scope results look empty, confirm you selected the correct reporting mode.

---

See also:
- [Documentation home](README.md)

---
