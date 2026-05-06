# Trusted data model (reconciliation)

SurveyTrace separates **what external sources reported** from **what the product currently believes** about an asset. Reconciliation turns observations into assertions and records how that happened.

This document reflects the **Milestone 1** implementation: **OS / platform**, **lightweight asset identity** (slice 4), and **trusted operational read preference** (slice 5). Other dimensions (CVE fusion, ownership reconciliation, device merge engines) are **not** implemented here.

---

## Stored fields vs trusted operational display (slice 5)

SQLite **`assets`** rows keep the **original inventory** from scans and enrichment (`hostname`, `os_guess`, `cpe`, …). Those columns are **not overwritten** by reconciliation.

**Observations** and **assertions** live in separate tables. Assertions summarize belief; observations preserve per-source evidence.

**Operational “trusted” API fields** (`trusted_hostname`, `trusted_hostname_confidence`, `trusted_os_platform`, `trusted_os_confidence`) are **additive read helpers**:

- Populated only when the matching assertion exists **and** confidence is **`medium`**, **`high`**, or **`authoritative`**.
- **`low`** confidence beliefs stay visible in **`recon_detail`** / **`identity_recon_detail`** but are **not** promoted into `trusted_*` (informational only).

**UI and exports** may **prefer** `trusted_*` for headings and table cells while still showing **stored** hostname / scan OS in the host **Identity & inventory** block and in **export columns** (`Hostname`, `OS Guess` unchanged; trusted values appended as extra CSV columns when reconciliation tables exist).

---

## Concepts

### Observations (`asset_observations`)

An observation is a **single fact** tied to an asset and a **recon source** (scanner, Zabbix, enrichment, operator, etc.): for example “this scan fingerprint”, “this inventory string from Zabbix”, or “operator hint”. Observations keep **raw** and **normalized** values where applicable, a coarse **confidence**, and **when** the source saw it (`observed_at`).

Observations are **append/update idempotently** from write paths (scanner, Zabbix sync, operator `PUT`). They do not, by themselves, change the UI “belief” until reconciliation runs.

### Assertions (`asset_assertions`)

An assertion is SurveyTrace’s **current belief** for a slice of trusted data. Implemented assertion types:

- **`os_platform`** — normalized OS bucket slug + human label.
- **`canonical_hostname`** — short DNS hostname label (lowercase) chosen from hostname/FQDN observations; **does not** merge assets or devices.

Assertions store a machine-oriented **`asserted_value`**, **confidence**, a short **explanation**, and **when** reconciliation last produced them.

The host modal and asset API expose OS summary fields after **lazy** OS reconciliation on host detail load, and identity summary fields (`canonical_hostname_*`) after **lazy** identity reconciliation in the same request.

### Assertion sources (`assertion_sources`)

When reconciliation picks an assertion, it links **which observations** supported that belief and how strongly (**contribution**, **weight note**). This answers: *“Why does SurveyTrace believe this value?”* for OS and for canonical hostname (hostname/FQDN rows plus optional anchors such as MAC, `device_id` link, IPv4, Zabbix host id).

### Reconciliation runs (`reconciliation_runs`)

Each reconciliation attempt on an entity (here: an **asset**) appends a row: **slice** (e.g. `os_platform`, `identity_hostname`), **status**, timestamps, optional **error** text, and optional **result summary** JSON. This is an **audit trail**, not a user-facing queue.

Failed runs are surfaced lightly in **System Health**; successful runs are mostly quiet.

---

## Identity observations (slice 4)

Additive `observation_type` values (no new tables):

| Type | Meaning |
|------|---------|
| `hostname_observed` | Short hostname label from scan, Zabbix, or operator |
| `fqdn_observed` | Full multi-label hostname when sources provide an FQDN |
| `ipv4_observed` | Asset IPv4 as seen on ingest |
| `mac_observed` | Normalized MAC from scan snapshot |
| `device_link` | `assets.device_id` linkage (evidence only) |
| `monitoring_hostid` | Linked Zabbix `hostid` |

**`canonical_hostname`** reconciliation prefers **FQDN + matching short label corroboration**, multi-source agreement, and optional **MAC / device** presence for higher confidence. **Authoritative** per-observation confidence is used for operator hostname edits. Conflicting hostname/FQDN rows **remain** in the database for audit; the UI can highlight them vs the current belief.

This slice **does not** auto-merge assets or devices, change collector behavior, or run fuzzy clustering.

---

## Lazy vs write path

- **Write paths** record observations; they **do not** eagerly re-run full reconciliation for every write (keeps ingest fast and predictable).
- **Lazy reconciliation** runs when an operator opens **Host Details** (single-asset `GET` in `assets.php`), so the displayed OS and identity beliefs are refreshed for that view without changing scanner or Zabbix ingest semantics beyond additive observation rows.

---

## Diagnostics

- **Host modal**: compact OS evidence plus **identity** block (`canonical_hostname_*`, `identity_recon_detail` with supporting vs conflicting observation ids where applicable). When confidence allows, the overview headline may prefer **`trusted_*`** fields while **stored** hostname / scan OS remain in Identity & inventory.
- **Assets list** (`GET /api/assets.php`): each row includes optional **`trusted_*`** fields; search matches canonical hostname / OS assertion slugs in addition to stored columns; hostname sort prefers reconciled short name when confidence is sufficient.
- **Exports** (`/api/export.php`): same additive **`trusted_*`** columns at the end of CSV / in JSON objects.
- **System Health** (`/api/health.php`): read-only `trusted_data` block (table readiness, OS + identity observation/assertion counts, approximate hostname-conflict asset count, recent failures, stale OS assertion hint).
- **Admin** (`/api/recon_diagnostics.php?asset_id=…`): OS payload in `recon` and identity payload in `identity_recon`; optional `include_sources=1`. POST `action=trim_runs` (with CSRF) trims old `reconciliation_runs` rows—see library helper `st_recon_trim_reconciliation_runs`.

---

## Retention

`reconciliation_runs` can grow without bound as assets are viewed and reconciled. Operators may trim via the admin diagnostics endpoint; adjust `keep` to retain more or fewer newest rows. This is intentionally simple—no background retention scheduler in this slice.

---

## Related code

- `api/lib_reconciliation.php` — reconciliation, health snapshot, evidence detail, trim helper
- `api/assets.php` — lazy OS + identity reconcile; `recon_detail` + `identity_recon_detail` on single-asset GET; operator hostname `PUT` writes identity observations
- `daemon/recon_observations.py` — scan-side identity observation writes
- `api/health.php` — `trusted_data`
- `api/recon_diagnostics.php` — admin asset diagnostics and optional trim
