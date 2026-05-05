# SurveyTrace Release Notes

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
