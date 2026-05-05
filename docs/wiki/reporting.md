# Reporting

[← Back to Documentation](README.md)

## When to use this

- Use this page when you need historical scan reporting or current inventory reporting.
- For full scope model definitions, see `concepts.md`.

## How to do it

### Step-by-step reporting usage

1. Open **Reports & Analysis**.
2. Select scope filter.
3. Choose reporting mode:
   - **Job scope** for historical scan snapshots.
   - **Inventory scope** for current asset state.
4. Review generated sections/cards.
5. If data is missing, validate mode/scope before deeper troubleshooting.

### How to choose job vs inventory scope

1. Use **Job scope** for drift/trend/compare questions.
2. Use **Inventory scope** for current posture/count questions.
3. If unsure, check `concepts.md` and run both views to compare expectations.

## What to expect

- Job scope mode shows scan-history-focused sections (trends/baselines/comparisons).
- Inventory scope mode shows current-state sections (asset/finding posture now).
- Named scopes with assets can still show empty job-mode data if no scoped jobs exist.

## Common issues

- **No data in job scope**
  - Scope may have assets but no completed scoped jobs; switch to inventory scope mode.
- **No data in inventory scope**
  - Scope assignment may be missing on assets.
- **Results differ between modes**
  - Expected: one is historical snapshots, the other is current state.
- **Users think reports are broken**
  - Usually mode/scope mismatch, not missing data pipeline.
- **Scope mismatch confusion**
  - Historical job scope and live inventory scope are intentionally separate models.
- **Inventory-only data expectation in job mode**
  - Run or complete a scoped scan if historical job output is required.

## Quick mode choice

- Use **Job scope** when you are answering "what did scans show over time?"
- Use **Inventory scope** when you are answering "what is true for this scope right now?"

---

See also:
- [Documentation home](README.md)

---
