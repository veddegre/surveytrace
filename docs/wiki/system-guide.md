# SurveyTrace System Guide

[← Back to Documentation](README.md)

## Overview

SurveyTrace combines network discovery, enrichment, and reporting into one operational system. Scanning discovers technical facts, enrichment adds external context, and reporting presents both historical and current-state views for decisions.

The name reflects the architecture:
- **Survey**: map what exists on the network through active/passive collection.
- **Trace**: keep continuity over time so operators can follow changes and risk.

## Data model

SurveyTrace keeps two data perspectives intentionally separate:
- **Scan jobs** are historical snapshots from completed runs.
- **Inventory** is the current asset/finding state.

They are separate so historical evidence is not overwritten by current updates.

High-level flow:
- Scan execution produces run-scoped results.
- Results are stored with job history.
- Asset records are created/updated for current-state inventory.
- Reporting reads either job history or inventory state, depending on mode.

## Scanning pipeline

At runtime, the scan path is:
- A scan is queued from Scan control or scheduler.
- Worker executes discovery/fingerprint phases.
- Run results are written to job-scoped history tables.
- Asset records are updated from processed findings.
- Completion status is published to Scan history and downstream views.

After completion:
- Historical analysis uses the finished job snapshot.
- Current inventory views use updated asset/finding state.

## Enrichment pipeline

Enrichment runs as contextual augmentation around scan/inventory data:
- Internal processing enriches discovered hosts with additional identity context.
- Zabbix sync pulls external host/monitoring state into local cache tables.
- Match workflows link external hosts to SurveyTrace assets explicitly.
- Linked trust signals (monitoring, availability, problem counts) are denormalized to assets for UI/reporting use.

## Reporting model

Reporting has two modes by design:
- **Job scope reports**: historical, based on completed scan jobs.
- **Inventory scope reports**: current state, based on scoped assets/findings.

This prevents model confusion:
- A scope can contain assets now but have no completed scoped jobs.
- In that case, job-scope views may be sparse while inventory-scope views remain populated.

Drift/comparison concepts:
- Drift and compare features rely on historical snapshot compatibility.
- Inventory views describe present posture, not past run deltas.

## Scheduler and workers

The scheduler coordinates recurring background operations:
- Evaluates scan schedules and queues due runs.
- Triggers Zabbix sync/output workers when due and configured.

Worker roles:
- **`zabbix_sync_worker`**: refreshes Zabbix cache data and updates link-derived trust fields.
- **`zabbix_output_worker`**: pushes SurveyTrace metrics to Zabbix when output is enabled.

Timing behavior:
- Scheduler uses configured intervals and due timestamps.
- “Stale” status appears when sync freshness exceeds expected interval windows.

## Integrations

### Zabbix

Zabbix integration includes:
- host/monitoring sync into local tables
- match review to connect external hosts to assets
- availability/problem trust propagation to linked assets
- optional output push through `zabbix_sender`

### AI enrichment

AI enrichment is optional contextual analysis:
- used to generate summaries/suggestions
- intended to assist operator review, not replace validation

## System health

System Health surfaces operational state across:
- core services/daemons
- storage/database readiness
- scheduler/integration status

Common status semantics:
- **Connected**: configured and healthy recent state
- **Degraded**: stale or warning condition
- **Error**: failed last operation or hard fault

## Common misunderstandings

- **“Reports are empty for this scope”**
  - Often a mode mismatch (job scope selected for inventory-only scope).
- **“Zabbix availability is unknown for monitored hosts”**
  - Usually stale sync, incomplete mapping, or missing availability fields from source.
- **“Assets exist but no scan history”**
  - Expected when assets are populated via enrichment/mapping rather than scoped scan runs.

## Design philosophy

SurveyTrace prioritizes operator clarity:
- keep **historical evidence** and **live state** separate
- require explicit enrichment/match actions for high-impact changes
- present workflow-oriented UI with clear status and health signals

---

See also:
- [Documentation home](README.md)

---
