# SurveyTrace Documentation

This directory contains documentation for both **operators** and **developers**.

---

## Start here

- [Wiki (operator documentation)](wiki/README.md)  
  Guides for installing, operating, and troubleshooting SurveyTrace.

---

## Operator documentation (wiki)

Located in `docs/wiki/`

Use this if you are:

- installing SurveyTrace
- running scans
- working with enrichment (Zabbix, AI, etc.)
- generating reports
- troubleshooting issues

Key entry point:

- [Wiki home](wiki/README.md)

Integration workflow references:

- [Integration Event Model](wiki/integrations-event-model.md)
- [Integrations (Data Flow)](wiki/integrations-data-flow.md)

---

## Advanced / internal documentation

These documents describe how SurveyTrace works internally or how to extend it.

### Trusted data (reconciliation)

- [Trusted data model](TRUSTED_DATA_MODEL.md)

Covers observations, assertions, assertion sources, and reconciliation runs (OS/platform scope in Milestone 1).

### Credentialed checks (design — not shipped product yet)

- [Credentialed Checks Engine — design](CREDENTIALED_CHECKS_ENGINE.md) — execution model, transports, credential safety, plugin framework.
- [Credentialed Checks — MVP implementation plan](CREDENTIALED_CHECKS_MVP_PLAN.md) — staged milestones before coding (planning doc; internal numbering is historical).

These documents support planning only until the engine is implemented.

### Background jobs and workers (design)

- [Worker / job execution substrate](WORKER_EXECUTION_SUBSTRATE.md) — shared queue semantics, leases, retries, cancellation, health visibility, and gradual migration from today’s split patterns (precursor to credentialed checks and clearer System Health).
- [Worker execution — MVP implementation plan](WORKER_EXECUTION_MVP_PLAN.md) — staged slices (schema, helpers, health, ingest mirror, cred-check native usage) before coding.

### Release process

- [Release readiness checklist](RELEASE_READINESS_CHECKLIST.md) — pre-tag verification for installs, workflows, trusted data, reporting, auth, and UI smoke.
- [Operational lifecycle and maintenance](OPERATIONAL_LIFECYCLE_MAINTENANCE.md) — manual maintenance workflows, backup/restore expectations, and admin runbooks.

### Device identity

- [Device identity](DEVICE_IDENTITY.md)

Explains how SurveyTrace separates:

- assets (IP-level)
- devices (logical systems)

Includes:

- identity model
- merge behavior
- API and UI behavior

---

### Connector development guide

- [Connector development guide](CONNECTOR_DEVELOPMENT_GUIDE.md)

Defines the standard pattern for building integrations:

- external data ingestion
- normalization and caching
- asset linking
- API and UI exposure

Use this when adding or modifying connectors.

---

## How to use this documentation

- New users → start with the **wiki**
- Daily operators → use **wiki workflows**
- Troubleshooting → use **wiki troubleshooting**
- Developers → use **internal docs**
- Release promotion → [RELEASE_READINESS_CHECKLIST.md](RELEASE_READINESS_CHECKLIST.md)

---

## Documentation structure

```text
docs/
  README.md                         ← this file
  TRUSTED_DATA_MODEL.md             ← observations / assertions / operational display
  CREDENTIALED_CHECKS_ENGINE.md     ← design (future authenticated checks)
  CREDENTIALED_CHECKS_MVP_PLAN.md   ← MVP implementation plan (pre-code)
  WORKER_EXECUTION_SUBSTRATE.md     ← shared job/worker execution design
  WORKER_EXECUTION_MVP_PLAN.md      ← staged MVP plan (pre-code)
  RELEASE_READINESS_CHECKLIST.md  ← pre-release verification
  DEVICE_IDENTITY.md                ← system design (identity model)
  CONNECTOR_DEVELOPMENT_GUIDE.md  ← integration pattern guide
  wiki/                             ← operator documentation
    README.md
    getting-started.md
    scanning.md
    enrichment.md
    reporting.md
    troubleshooting.md
    ...
```

---

## Notes

- The wiki is **task-focused and operator-oriented**
- The root docs are **system and developer references**
- Both are maintained together to ensure consistency across the platform