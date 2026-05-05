# Reporting

[← Back to Documentation](README.md)

## When to use this

- Use this page when you need historical scan reporting or current inventory reporting.
- For full scope model definitions, see `concepts.md`.

## How to do it

1. Open **Reports & Analysis**.
2. Pick report mode:
   - **Job scope reports** for historical scan evidence.
   - **Inventory scope reports** for current asset state.
3. Select the scope filter.
4. Review generated cards/sections.
5. If results look empty, switch mode before troubleshooting further.

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

## Quick mode choice

- Use **Job scope** when you are answering "what did scans show over time?"
- Use **Inventory scope** when you are answering "what is true for this scope right now?"

---

See also:
- [Documentation home](README.md)

---
