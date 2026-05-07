# SurveyTrace Roadmap

This document outlines the capability tracks and future direction of SurveyTrace.

It is organized by system areas rather than release phases or timelines.
Items may be active, planned, or deferred depending on external dependencies and platform priorities.

## Monitoring enrichment

### Current state

- Zabbix integration implemented:
  - JSON-RPC sync into SQLite cache
  - match/review/apply workflows
  - scheduler-driven sync with freshness tracking
  - optional SurveyTrace -> Zabbix metrics output

### Active areas of improvement

- additional diagnostics and troubleshooting visibility
- improved sync transparency and error surfacing
- refinement of availability and monitoring signals

### Planned or deferred work

- no deferred items currently identified for this track

### Notes

- This track is focused on monitoring context.
- It does NOT include ownership or endpoint/XDR-style enrichment.

## UI and operator workflows

### Current state

- Core UI workflows implemented:
  - assets, scanning, enrichment, reporting, system health

### Active areas of improvement

- filter usability and consistency improvements
- enrichment UX refinements
- scan history enhancements (pagination, filtering, deep links, export)
- bulk operations
- fingerprint pattern editor improvements
- removal of native alert/confirm/prompt usage
- optional modularization of public/index.php

### Planned or deferred work

- ongoing UI hardening and workflow polish as additional operator patterns emerge

### Notes

- Design references:
  - docs/UI_CLEANUP_PLAN.md (historical reference, not active spec)
  - docs/NAV_REDESIGN.md (navigation concepts)

## Connector framework

### Current state

- Zabbix is the reference implementation.
- Connector pattern established:
  - config -> sync -> cache -> link -> review -> apply

### Active areas of improvement

- standardization of:
  - auth handling
  - paging and limits
  - health/status reporting
  - worker patterns
- improved RBAC handling for connector actions

### Planned or deferred work

- codification of connector templates and implementation checklists for new integrations

### Reference

- docs/CONNECTOR_DEVELOPMENT_GUIDE.md

## Ownership and endpoint enrichment

### Current state

- ownership and endpoint enrichment connectors are not currently active

### Active areas of improvement

- requirements and data model boundaries are being refined for future connector implementation

### Planned or deferred work

- **Deferred:** TeamDynamix-style ownership and business context
- **Deferred:** Microsoft Defender-style endpoint/device/CVE enrichment

### Constraints

- TeamDynamix:
  - deferred until API/Swagger stabilizes
- Microsoft Defender:
  - deferred until testable environment or representative dataset exists

### Notes

- This track is about external system context, not scanning or monitoring.

## Infrastructure / API connectors

### Current state

- Some passive fingerprinting exists today.

### Active areas of improvement

- readiness work for first-class API-backed enrichment pipeline expansion

### Planned or deferred work

First-class API-backed enrichment for systems such as:

- Proxmox
- VMware
- TrueNAS
- Cisco (DNA / Meraki)
- Juniper Mist
- Infoblox
- Palo Alto

### Notes

- This track focuses on API-driven context enrichment.
- Vendor priority/order is not fixed.

## Data fusion and source reconciliation

### Current state

- initial vulnerability and enrichment foundations exist, but multi-source reconciliation is not yet implemented

### Active areas of improvement

- data model preparation for cross-source normalization and confidence handling

### Planned or deferred work

- multi-source CVE/advisory correlation
- source weighting and conflict resolution
- integration of:
  - NVD
  - KEV
  - EPSS
  - OSV (future)
- reconciliation between:
  - scan results
  - enrichment sources
  - external vulnerability feeds

### Dependencies

- requires multiple active enrichment sources

## Credentialed checks engine

### Current state

- **MVP slice 1 (schema):** additive SQLite tables `credential_profiles`, `credential_check_plugins`, `credential_check_jobs`, `credential_check_runs`, `credential_check_run_targets`, `credential_check_results`, `credential_check_artifacts` plus migration marker `migration_credentialed_checks_v1` ([docs/CREDENTIALED_CHECKS_MVP_PLAN.md](docs/CREDENTIALED_CHECKS_MVP_PLAN.md))
- **MVP slice 2 (plugin registry):** built-in manifest definitions, `st_cred_seed_builtin_plugins` on `st_db()` bootstrap, `api/lib_credentialed_checks.php`, admin-only read-only `api/credentialed_checks.php` — **no execution**
- **MVP slice 3 (credential profiles):** admin-only `api/credential_profiles.php` + `api/lib_credential_profiles.php`, Settings UI card — metadata + scope
- **MVP slice 4 (credential secrets):** `api/lib_secrets.php` (`SURVEYTRACE_CRED_SECRET_KEY`), encrypted `secret_ciphertext`, `set_secret` / `clear_secret` — **no plugin execution**
- **MVP slice 5 (transport handshake test):** `api/lib_credential_profile_transport_test.php`, `daemon/cred_transport_*.py`, `POST action=test` — **SSH + SNMPv3** only (paramiko + pysnmp), explicit target host, audits `credential_profile.test_*` — **no worker_jobs / observations**
- credentialed check **execution** (SSH / WinRM / SNMP plugins) is not yet implemented

### Active areas of improvement

- framework and execution model definition for authenticated checks

### Planned or deferred work

- authenticated scanning:
  - SSH
  - WinRM
  - SNMPv3
  - API-based checks where appropriate

Capabilities:

- plugin/check framework
- package/version-level evidence
- remediation metadata

### Notes

- This is distinct from API enrichment.
- This executes checks on systems, not just pulling external data.
- Shared **job/worker execution** concepts (queues, leases, retries, health) are described in [docs/WORKER_EXECUTION_SUBSTRATE.md](docs/WORKER_EXECUTION_SUBSTRATE.md) as a precursor to credentialed checks and broader observability.

## Worker and job execution substrate

### Current state

- background work is spread across systemd services, PHP CLI workers, Python daemons, and database-specific queues without a single shared job model
- **MVP slice 1 (schema):** additive SQLite tables `worker_nodes`, `worker_jobs`, `worker_job_attempts`, `worker_job_events`, `worker_heartbeats` plus migration marker `migration_worker_execution_substrate_v1` — **no runtime wiring** yet ([docs/WORKER_EXECUTION_MVP_PLAN.md](docs/WORKER_EXECUTION_MVP_PLAN.md))

### Active areas of improvement

- helper library, health visibility, and adapters on top of the substrate tables ([docs/WORKER_EXECUTION_MVP_PLAN.md](docs/WORKER_EXECUTION_MVP_PLAN.md))

### Planned or deferred work

- gradual adoption per [docs/WORKER_EXECUTION_SUBSTRATE.md](docs/WORKER_EXECUTION_SUBSTRATE.md) (e.g. collector ingest first, credentialed checks when implemented, Zabbix/scan paths later or read-only mirrored only)
- implementation sequencing: [docs/WORKER_EXECUTION_MVP_PLAN.md](docs/WORKER_EXECUTION_MVP_PLAN.md)

### Notes

- does not replace systemd as the primary supervisor in the near term
- see [Design approach](#design-approach) for workflow and observability priorities

## Risk operations and governance

### Current state

- base reporting controls exist via existing reporting workflows

### Active areas of improvement

- framing of governance controls and risk signal composition on top of current reporting data

### Planned or deferred work

- composite risk scoring
- time-bound suppressions / exceptions
- SLA tracking
- improved audit and reporting controls

## Design approach

SurveyTrace development prioritizes:

- explicit operator workflows over hidden automation
- clear separation of system concerns
- stable data models
- visibility into system state and behavior
