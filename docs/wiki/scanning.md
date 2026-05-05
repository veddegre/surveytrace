# Scanning

[← Back to Documentation](README.md)

## When to use this

- Use this page when you need to run scans, monitor queue state, and review results quickly.

## How to do it

1. Go to **Scan control**.
2. Select scan profile and options.
3. Enter target CIDR/range.
4. Click **Start scan**.
5. Open **Scan history** to watch queue and run status.
6. Open the completed run for details.
7. Re-run from scan history if you need a fresh snapshot.

## What to expect

- Scan appears as **queued**, then **running**, then **done/failed/aborted**.
- Completed jobs remain as historical snapshots.
- Assets/finding views update after processing completes.
- Results are visible in **Scan history**, **Assets**, and **Host details**.

## Common issues

- **Scan stays queued**
  - Scanner daemon may be down; check service status.
- **Scan fails quickly**
  - Target/options may be invalid or unreachable.
- **No new assets after completion**
  - Run may have found nothing, or filters hide results.
- **Need to compare with prior runs**
  - Use reports and pick job-based history mode.

---

See also:
- [Documentation home](README.md)

---
