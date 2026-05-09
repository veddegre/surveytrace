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

### Inventory ownership tracking (TODO — not implemented)

Capture requirements only; **do not treat as scheduled work** until prioritized.

**Future capability**

- Track **asset/host owner** as a first-class concern (not buried in notes or informal tags).
- Ingest **ownership evidence from Zabbix inventory** via **flexible field mapping** (which host inventory keys map to “owner” is operator-defined where possible).
- **Host Details / Edit Host:** explicit **ownership override** workflow (RBAC as appropriate).
- **Preserve provenance by source:**
  - Zabbix-provided owner
  - manually overridden owner
  - future ITSM / **TeamDynamix** owner (when that connector ships)
- **Precedence:** manual override should drive **operational** owner (UI, exports, downstream hooks) **without** erasing or replacing underlying source evidence rows.
- **Trusted-data alignment (eventual):**
  - observations such as **`owner_observed`** (per-source or normalized — TBD)
  - assertion such as **`owner_assertion`** or **`canonical_owner`**
  - **`assertion_sources`** wiring and **explanation / confidence** consistent with [docs/TRUSTED_DATA_MODEL.md](docs/TRUSTED_DATA_MODEL.md)

**Design guardrails for adjacent work** (inventory reconciliation, software evidence, host edit API)

- Prefer schema and APIs that do **not** make ownership hard to add later (avoid painting corners with single free-text “owner” columns without observation/assertion separation).
- Keep **host edit** and asset PATCH-style flows **extensible** for additional reconciled fields.
- Keep **Zabbix inventory → SurveyTrace** mapping **flexible** (configuration over hard-coded field names).
- **Do not** overload **`notes`**, generic **tags**, or other catch-all fields for ownership — reserve them for their intended semantics.

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

- initial vulnerability and enrichment foundations exist; **multi-source CVE/advisory fusion is not implemented**
- **Software Inventory Reconciliation Foundations — summary layer (complete):**
  - **`software_observed`** observations with bounded cardinality from credentialed package inventory collection (replace semantics for latest inventory per asset/run; **`package_inventory_observed`** summary retained alongside row-level evidence)
  - a single reconciled **`software_inventory_summary`** assertion per asset (confidence reflects freshness, partial/truncated/bounded signals, and inventory completeness — **not** vulnerability posture)
  - host-facing evidence preview, **slice 3–4** **`trusted_data`** diagnostics (stale/partial summaries, **`software_observed`** gaps, bounded readiness counters — **counts only**), and admin **`recon_diagnostics`** software block; reconciliation explanations remain **evidence/freshness-first** with **no CVE authority**; **no per-package authoritative assertions**, **no findings or remediation** derived from this path
- package inventory today supports **bounded evidence** and **summary-level trusted assertions** only; it does **not** drive vulnerability decisions

### Active areas of improvement

- data model preparation for cross-source normalization and confidence handling
- software identity normalization improvements (naming/version/source alignment) ahead of any advisory correlation

### Planned or deferred work

- **Deferred:** multi-source **CVE/advisory correlation** (NVD, KEV, EPSS, OSV as future inputs) until inventory reconciliation foundations mature
- **Deferred:** automated **finding generation** and **remediation** workflows grounded in reconciled software identity — only after normalization, source weighting, and scaling/retention posture are reviewed
- source weighting and conflict resolution across enrichment and inventory signals
- retention/scaling review for observation volume caps and reconciliation churn
- reconciliation between (future): scan results, enrichment sources, external vulnerability feeds — **today there is no CVE fusion pipeline**

### Dependencies

- CVE-centric fusion requires multiple active enrichment feeds **and** mature software identity reconciliation; neither is a substitute for the current summary-only inventory assertions

## Credentialed checks engine

### Current state

- **Software Inventory Reconciliation Foundations — Slice 1 (complete):**
  - **`software_observed`** observation type
  - bounded writes from **`ssh.linux.package_inventory`** (cap of **128** software observations per asset/run)
  - replace semantics for latest package inventory; **`package_inventory_observed`** summary retained
  - **no** CVE, finding, or remediation logic in this path
- **Software Inventory Reconciliation Foundations — Slice 2 (complete):**
  - **`software_inventory_summary`** assertion (**one** summary assertion per asset — not per package)
  - confidence rules for fresh vs partial/truncated/bounded vs stale inventory signals
  - host modal **Software inventory** evidence block and optional **System Health** counts for software summaries
  - validation: `daemon/st_software_observation_selftest.py`, `scripts/st_software_inventory_summary_selftest.php`
- **Software Inventory Reconciliation Foundations — Slice 3 (complete):**
  - host modal polish: explicit **source**, **stale/partial** wording, **View software evidence** disclosure (bounded preview only — **no** full package list in default API/UI)
  - **`trusted_data`** diagnostics: stale summaries, partial summaries, **`software_observed`** without summary assertion (quiet when counts are zero)
  - admin **`recon_diagnostics`** read-only **`software_inventory`** block (no new execution paths)
  - validation: `scripts/st_software_inventory_evidence_selftest.php` (plus slice 1–2 tests above)
- **Software Inventory Reconciliation Foundations — Slice 4 (complete):**
  - resolver **explainability**: explicit **`medium`**/**`low`** rationale tied to freshness, partial/truncated/bounded inventory, stale bands (**≤180d vs >180d reporting**), and **`software_inventory_observation_gap`** when summaries rely on **`package_inventory_observed`** without **`software_observed`** corroboration (evidence-only — **no** CVE authority)
  - single-asset JSON: **`software_inventory_stale_band`**, **`software_inventory_has_bounded_observations`**, **`software_inventory_observation_gap`**
  - **`trusted_data`** readiness counts (stale age splits, repeat partial package inventories, reconciliation drift hints, summaries lacking bounded rows) — **scalar diagnostics only**
  - fusion posture documented for future **scanner / API / SBOM / agent** inventory — **no new ingestion paths** in slice 4
  - validation: `scripts/st_software_inventory_diagnostics_selftest.php` (plus slices 1–3 tests above)
- **Future (not started here):** stronger software identity normalization, cross-source weighting, retention/scaling policy review, eventual CVE/advisory correlation, eventual finding generation **after** reconciliation foundations mature (see [docs/TRUSTED_DATA_MODEL.md](docs/TRUSTED_DATA_MODEL.md), [docs/CREDENTIALED_CHECKS_ENGINE.md](docs/CREDENTIALED_CHECKS_ENGINE.md))
- **MVP slice 1 (schema):** additive SQLite tables `credential_profiles`, `credential_check_plugins`, `credential_check_jobs`, `credential_check_runs`, `credential_check_run_targets`, `credential_check_results`, `credential_check_artifacts` plus migration marker `migration_credentialed_checks_v1` ([docs/CREDENTIALED_CHECKS_MVP_PLAN.md](docs/CREDENTIALED_CHECKS_MVP_PLAN.md))
- **MVP slice 2 (plugin registry):** built-in manifest definitions, `st_cred_seed_builtin_plugins` on `st_db()` bootstrap, `api/lib_credentialed_checks.php`, admin-only read-only `api/credentialed_checks.php` — **no execution**
- **MVP slice 3 (credential profiles):** admin-only `api/credential_profiles.php` + `api/lib_credential_profiles.php`, Settings UI card — metadata + scope
- **MVP slice 4 (credential secrets):** `api/lib_secrets.php` (`SURVEYTRACE_CRED_SECRET_KEY`), encrypted `secret_ciphertext`, `set_secret` / `clear_secret` — **no plugin execution**
- **MVP slice 5 (transport handshake test):** `api/lib_credential_profile_transport_test.php`, `daemon/cred_transport_*.py`, `POST action=test` — **SSH + SNMPv3** only (paramiko + pysnmp), explicit target host, audits `credential_profile.test_*` — **no worker_jobs / observations**

### Scan workflow integration (next work; explicit operator choice required)
- Scan launch and schedule flows currently choose scan coverage/rates only; credential profile binding is still handled in **Credentialed Checks jobs**.
- **TODO (product):** attach optional **credential profile / credentialed check job** to **scan start** (UI + API), default **none**, with audit parity to job-based runs.
- **TODO (product):** attach the same optional linkage to **scheduled scan** definitions so repeats never gain credentialed execution implicitly.
- **TODO (engineering):** **scope-compatible target filtering** when a scan has a `scope_id` — only targets (or assets) allowed by the profile’s `scope_json` (and job policy) may be offered or executed.
- **TODO (safety):** **no silent credential execution** — any scan-linked cred path requires an explicit operator-visible mode (e.g. discover-only vs discover+credentialed) and must not run merely because a scan exists.
- Add an explicit scan/schedule option to select **credential profile (optional)**, with a safe default of **none selected**.
- Filter profile choices by scope compatibility (`scope_json.scope_ids` allowlist) when the scan/schedule has a selected `scope_id`.
- Require an explicit run-mode choice before credentialed execution is allowed from scan contexts (for example: discover-only vs discover+credentialed), so credentialed checks never start silently.
- Keep existing job-based credentialed checks as the stable path until the scan-linked execution mode has equivalent auditability and operator controls.
- **SSH**-backed **package inventory** collection is implemented as part of Software Inventory foundations above; **WinRM**, broader production **SNMP** inventory plugins (beyond handshake/testing paths), and **API-based** authenticated checks remain MVP-plan work

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
- bounded package/version-level **observations** and **summary assertions** (Slice 1–2); **not** per-package vulnerability authority
- **Deferred:** remediation metadata tied to reconciled risk findings (no remediation product today)

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
- credentialed **software inventory** outputs **summary-level** reconciliation and bounded evidence only — **no** vulnerability findings, **no** CVE-driven alerts, **no** remediation workflows from package inventory

### Active areas of improvement

- framing of governance controls and risk signal composition on top of current reporting data

### Planned or deferred work

- composite risk scoring
- time-bound suppressions / exceptions
- SLA tracking
- improved audit and reporting controls
- **Deferred:** governance workflows that assume **CVE-matched package findings** or authoritative per-package risk assertions — blocked until advisory correlation and identity normalization mature (see [Data fusion and source reconciliation](#data-fusion-and-source-reconciliation))

## Design approach

SurveyTrace development prioritizes:

- explicit operator workflows over hidden automation
- clear separation of system concerns
- stable data models
- visibility into system state and behavior
- reconciliation-first expansion for software inventory: deepen **identity normalization**, **source weighting**, and **retention/scaling** before **CVE/advisory correlation** or **finding generation** that would depend on trustworthy fused identity
