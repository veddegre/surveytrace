# SurveyTrace Release Notes

## Unreleased

## 1.0.4 (2026-05-07)

SurveyTrace **1.0.4** ships **Software Inventory Reconciliation Foundations (slices 1–4)** on the trusted-data model: bounded **`software_observed`** rows from credentialed SSH package inventory, a single lazy **`software_inventory_summary`** assertion per asset, Host modal **software evidence** (bounded preview only), and **System Health / `trusted_data`** readiness counters for operators.

### What changed for operators

- **Bounded inventory observations** — Per successful package inventory, up to **128** deduped **`software_observed`** identities per asset (latest run replaces prior bounded rows for that plugin path); full lists stay in check results/artifacts, **not** in the default Host/API surface.
- **Reconciled inventory summary** — One **`software_inventory_summary`** belief per asset (**`medium`**/**`low`** from freshness and completeness only — **not** CVE exposure); explanations state **no CVE matching** and **no findings** from this path.
- **Host modal** — **Evidence — Software evidence (bounded inventory)**: source line, confidence chip, stale/partial/**observation-gap** badges where applicable, **`View software evidence`** disclosure (≤**3** sample rows).
- **Health diagnostics** — Quiet when healthy; non-zero **`trusted_data`** signals for software summaries (stale bands, partial repeats, drift hints, summaries without **`software_observed`**, etc.).
- **Install/deploy validation** — **`setup.sh`** / **`deploy.sh`** verify and **`php -l`** the software inventory selftests (`slice2`–`slice4`, **`st_recon_slice10_selftest.php`**) alongside existing reconciliation/cred-check validation.

### Deferred by design

- **No CVE matching**, **no vulnerability findings**, **no remediation** driven from package inventory or software reconciliation in this release.
- **No new execution transports** for inventory beyond existing SSH package inventory behavior documented for cred checks.
- Multi-source inventory fusion (**scanner / APIs / SBOM / agents**) remains **documentation / resolver posture only** until explicit ingest ships.

### What to verify after upgrade

- From repo clone:  
  `python3 daemon/st_software_obs_slice1_selftest.py`  
  `php scripts/st_software_inventory_slice2_selftest.php`  
  `php scripts/st_software_inventory_slice3_selftest.php`  
  `php scripts/st_software_inventory_slice4_selftest.php`  
  plus existing slice **7/8/9**, **`php scripts/st_recon_slice10_selftest.php`**, and **`bash scripts/smoke_credential_checks_placeholder.sh`** (optional CI parity).
- **`bash -n setup.sh`** and **`bash -n deploy.sh`** after script edits.
- UI: open a host with cred package inventory — software evidence block renders; **System Health** trusted-data line stays readable when software counters are zero.

## 1.0.3 (2026-05-07)

SurveyTrace **1.0.3** is a **stabilization and clarity** update on the 1.0 line. It tightens **deployment validation** for systemd-sandboxed daemons that touch SQLite, stabilizes the **Settings** workspace (tabs, reference separation, single-column layout), and aligns **credentialed checks** messaging with what is already shipped. **Operational lifecycle CLI tooling** shipped in **1.0.2** is unchanged; this release documents and verifies surrounding fixes.

### What changed for operators

- **systemd / SQLite** — `setup.sh` and `deploy.sh` can **fail fast** if installed master units omit **`ReadWritePaths`** for the data directory, reducing “ingest running but DB errors in journal” confusion when `ProtectSystem=strict` is in effect.
- **Settings** — Clearer subtab grouping, **Reference** vs configuration separation, and a **full-width vertical stack** of cards for readability (no multi-column card masonry on Settings).
- **Credentialed checks** — Help and Settings copy reflect **live** SSH/SNMPv3 checks, worker-backed runs, and bounded artifacts; less “planned future” wording where capability already exists.

### What to verify after upgrade

- `systemctl cat surveytrace-collector-ingest.service` (and other master daemons) show **`ReadWritePaths`** covering your install’s `data` path; re-run **`deploy.sh`** or refresh units from the repo if not.
- Quick pass: **Settings** → each subtab (Platform → Reference) — cards align left and fill width; **Credentialed Checks** subtab content (profiles, jobs, operational readouts) renders correctly for admins.

## 1.0.2 (2026-05-07)

SurveyTrace **1.0.2** completes the **Operational Lifecycle and Maintenance** milestone. This release is focused on long-term survivability and operator safety: explicit manual maintenance tooling, read-only maintenance visibility, and backup/restore validation guidance.

### What changed for operators

- **Manual maintenance toolkit (CLI-first)**:
  - `scripts/rewrap_credential_secrets.php`
  - `scripts/prune_operational_history.php`
  - `scripts/recover_stale_worker_jobs.php`
  - `scripts/validate_backup_restore_readiness.php`
- **Admin maintenance visibility** — System Health and Settings now show read-only maintenance signals and runbook references; no browser-triggered maintenance actions were added.
- **Backup/restore readiness clarity** — explicit required backup set, restore order, post-restore validation, and key parity guidance across web/API and worker nodes.
- **Runbook/checklist polish** — release readiness now includes maintenance dry-runs and backup/restore validation checks.

### Deferred by design

- No automatic prune scheduler or stale-job sweeper.
- No cloud backup integration.
- No Vault/KMS integration.
- No new credentialed check transports or capability expansion in this milestone.

## 1.0.1 (2026-05-06)

SurveyTrace **1.0.1** is a **stabilization and maintenance** update on the 1.0 line. It improves day-to-day operator experience, clarifies collector handoff to the master, tightens **deployment parity** for newer libraries and docs, and documents the **trusted data** model and future **credentialed checks** direction **without** shipping credentialed execution yet.

### What changed for operators

- **Clearer investigation UI** — Host details and workspace polish, including light-mode readability and modal behavior, make triage and evidence review faster with less eye strain.
- **Collector reliability signals** — When a collector has submitted results, the master UI better reflects **ingest progress** (waiting, retrying, or failed) so you know whether to wait, check services, or open Scan History for detail.
- **Trusted data visibility** — OS/platform and identity (canonical hostname) evidence is easier to find; reconciled values may appear in lists and exports **when confidence is sufficient**, while **stored scan inventory** stays visible so nothing feels “silently rewritten.”
- **Safer upgrades** — `deploy.sh` and `setup.sh` now explicitly ship and validate reconciliation-related PHP/Python files and ship **operator documentation** under `/opt/surveytrace/docs/`, reducing “works in git but missing on server” drift.

### What to read next

- **[Trusted data model](docs/TRUSTED_DATA_MODEL.md)** — how observations, assertions, and UI “trusted” hints relate.
- **[Release readiness checklist](docs/RELEASE_READINESS_CHECKLIST.md)** — optional full verification before your own production promotion.
- **Credentialed checks** — [design](docs/CREDENTIALED_CHECKS_ENGINE.md) and [MVP plan](docs/CREDENTIALED_CHECKS_MVP_PLAN.md) describe a **future** authenticated-check engine; they are **not** user-facing product features in 1.0.1.

---

## 1.0.0 (2026-05-05)

SurveyTrace 1.0.0 is the first stable release of SurveyTrace.

SurveyTrace is a security and asset visibility platform for operators and security teams that combines scanning, enrichment, vulnerability tracking, and reporting in one interface.

### What changed leading up to 1.0

- Dashboard mode and navigation polish for faster at-a-glance operations
- Host Details redesign for clearer investigation workflows
- Reports and Enrichment UX updates, including explicit job-scope vs inventory-scope reporting
- Broader UI consistency pass for tables, controls, and role-aware visibility
- Improved deployment/setup validation parity across master and collector scripts
- Zabbix integration status visibility in Health and Enrichment views

### Key capabilities

- Asset discovery and inventory tracking
- Vulnerability lifecycle tracking and triage
- Enrichment from Zabbix and optional AI summaries
- Reporting and analysis across historical scans and current inventory
- Role-based access control for viewer, scan editor, and admin roles
- Distributed scanning with optional collector nodes

### Intended audience

- Security operators who need actionable vulnerability and exposure context
- Infrastructure and network teams maintaining asset visibility
- Teams that need lightweight self-hosted scanning with role-aware workflows

---

## Earlier versions

Per-version technical history for releases before 1.0.0 is recorded in [CHANGELOG.md](CHANGELOG.md). That history covers reporting and baselines, integrations (push/pull and per-integration tokens), scan scopes, Zabbix monitoring enrichment, asset lifecycle, CVE intelligence feeds, change detection, collectors, and successive hardening passes that led to this stable line.
