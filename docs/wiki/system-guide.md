# SurveyTrace System Guide

[← Back to Documentation](README.md)

## Overview

SurveyTrace combines network discovery, enrichment, and reporting into one operational system.

- **Scanning** discovers technical facts about systems.
- **Enrichment** adds external context and trust signals.
- **Reporting** presents both historical and current-state views.

The name reflects the architecture:

- **Survey** — systematically discover what exists on the network.
- **Trace** — maintain continuity over time to understand change and risk.

This separation allows operators to answer both:

- *What is happening right now?*
- *What changed over time?*

---

## Data model

SurveyTrace intentionally separates two perspectives:

- **Scan jobs** → historical snapshots  
- **Inventory** → current asset and finding state  

This separation ensures:

- historical evidence is preserved
- current updates do not overwrite past results

---

### Data flow

```text
scan → job results → processing → asset updates → inventory
```

- Scan results are written to **job history**
- Relevant data is propagated to **inventory**
- Reporting reads from one or the other depending on mode

---

### Why this matters

- You can always trust historical reports
- Inventory can evolve without corrupting past data
- Debugging becomes clearer (history vs current state)

---

## Scanning pipeline

### Runtime flow

1. Scan is created (manual or scheduled)
2. Job enters queue
3. Scanner executes:
   - discovery
   - fingerprinting
4. Results are written to job history
5. Asset records are updated
6. Job status is finalized

---

### After completion

- **Scan history** → immutable snapshot
- **Inventory** → updated current state
- **Reporting** → uses selected mode

---

### Key property

- Scan jobs are **immutable**
- Inventory is **mutable**

---

## Enrichment pipeline

Enrichment augments scan-derived data with external context.

### Flow

1. External system sync (e.g., Zabbix)
2. Data stored in local cache tables
3. Match workflow links:
   - SurveyTrace asset ↔ external entity
4. Linked fields are applied to assets

---

### What enrichment adds

- monitoring state
- availability
- external identifiers
- contextual trust signals

---

### Important behavior

- Matching is **explicit**
  - nothing is auto-linked without review
- Enrichment updates:
  - inventory only (not job history)

---

## Reporting model

SurveyTrace has two distinct reporting modes:

---

### Job scope reports

- Based on **scan_jobs**
- Used for:
  - trends
  - comparisons
  - drift analysis

Requirements:
- completed scan jobs for that scope

---

### Inventory scope reports

- Based on **assets**
- Used for:
  - current posture
  - counts and grouping
  - live risk state

---

### Key distinction

| Mode            | Data source | Purpose              |
|-----------------|------------|----------------------|
| Job scope       | scan_jobs  | historical analysis  |
| Inventory scope | assets     | current state        |

---

### Common behavior

- A scope can:
  - have assets (inventory)
  - but no job history

Result:
- job reports → empty
- inventory reports → populated

This is expected behavior, not an error.

---

## Scheduler and workers

The scheduler is the coordination engine.

---

### Responsibilities

- evaluate schedules
- queue scan jobs
- trigger integration workers
- manage timing and execution windows

---

### Workers

- **zabbix_sync_worker**
  - pulls Zabbix data into local cache
  - updates asset-linked fields

- **zabbix_output_worker**
  - pushes SurveyTrace metrics to Zabbix

---

### Timing model

- based on:
  - interval configuration
  - last run timestamps
- scheduler determines when tasks are “due”

---

### “Stale” meaning

- last successful run exceeded expected interval
- indicates:
  - scheduler issue
  - worker failure
  - or missed execution

---

## Integrations

### Zabbix

Zabbix integration provides:

- host sync
- match linking
- availability propagation
- optional output push

---

### Availability model

Availability is derived from:

- host-level fields
- interface-level fields

Mapped to:

- `available`
- `unavailable`
- `unknown`

---

### Why “unknown” happens

- no availability fields returned
- host not monitored
- mapping not applied
- sync not run

---

### AI enrichment

AI is optional and assistive:

- generates summaries
- suggests classifications
- does **not replace operator decisions**

---

## System health

System Health aggregates:

- service state
- scheduler status
- integration status
- storage readiness

---

### Status meanings

- **Connected**
  - healthy, recent success

- **Degraded**
  - stale or partial success

- **Error**
  - last operation failed

---

### Purpose

- quickly identify system-wide issues
- reduce need for manual log inspection

---

## Common misunderstandings

### “Reports are empty”

- usually:
  - job mode selected
  - but no scan jobs exist

---

### “Zabbix shows unknown”

- sync not run
- mapping not applied
- API not returning fields

---

### “Assets exist but no history”

- assets created via:
  - enrichment
  - partial scans
- no completed jobs for that scope

---

### “Enrichment should affect reports”

- only affects inventory
- job reports remain historical

---

## Design philosophy

SurveyTrace prioritizes:

---

### Separation of concerns

- historical vs current data
- internal vs external context

---

### Operator control

- explicit actions over automation
- visible workflows instead of hidden logic

---

### Debuggability

- clear data sources
- predictable behavior
- minimal hidden state

---

### Practical outcome

Operators can:

- trust historical reports
- understand current posture
- diagnose issues without guessing

---

See also:
- [Concepts](concepts.md)
- [Reporting](reporting.md)
- [Enrichment](enrichment.md)
- [Documentation home](README.md)