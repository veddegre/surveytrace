# SurveyTrace Release Notes

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
