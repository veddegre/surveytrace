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
| `hostname_observed` | Short hostname label from scan, Zabbix, operator edits, or **SNMP sysName** via **`credentialed_check`** (slice 9 — `daemon/recon_observations.py` **`upsert_cred_snmp_sysname_observations`**) |
| `fqdn_observed` | Full multi-label hostname when sources provide an FQDN (including SNMP **sysName** when it looks like an FQDN — **slice 9**) |
| `ipv4_observed` | Asset IPv4 as seen on ingest |
| `mac_observed` | Normalized MAC from scan snapshot |
| `device_link` | `assets.device_id` linkage (evidence only) |
| `monitoring_hostid` | Linked Zabbix `hostid` |

**`canonical_hostname`** reconciliation prefers **FQDN + matching short label corroboration**, multi-source agreement, and optional **MAC / device** presence for higher confidence. **Authoritative** per-observation confidence is used for operator hostname edits. Conflicting hostname/FQDN rows **remain** in the database for audit; the UI can highlight them vs the current belief.

This slice **does not** auto-merge assets or devices, change collector behavior, or run fuzzy clustering.

---

## Observations from credentialed checks (MVP slices 7–9)

| Type | Meaning |
|------|---------|
| `os_version_observed` | Linux `/etc/os-release`-derived label (for example `PRETTY_NAME`); `normalized_value` uses the same slug family as scan-side OS text (`daemon/recon_observations.py` / `st_recon_normalize_os_text`). Recon source `credentialed_check`; `source_object_ref` ties to run, target row, and plugin version. |
| `package_inventory_observed` | **Summarized** credentialed package inventory evidence: `normalized_value` holds a short deterministic digest (package manager, total count, hash prefix over a bounded prefix of stored package rows). `raw_value` is a small JSON summary (counts, flags, `result_id` / `run_id`). **Not** per-package `package_installed` rows — full bounded package list remains in **`credential_check_results`** / stdout artifact only. **No CVE matching**, no software assertions from this slice. **`source_object_ref` includes `run_id`** → **one observation row per completed package-inventory result**, not per package; long-term volume tracks **run cadence** (see retention note in [Credentialed checks engine](CREDENTIALED_CHECKS_ENGINE.md) slice 8). |
| `software_inventory_snapshot_observed` | **One summary row per credentialed target** after package inventory: small JSON in `raw_value` with `package_manager`, `package_count`, **`packages_added` / `packages_removed` / `packages_changed`**, `active_rows_after`, flags, `run_id` / `result_id`. **Normalized** package identities live in **`software_inventory` / `software_inventory_versions` / `software_inventory_asset_state`** (durable per asset; **`active`** flips when packages disappear). **No** per-package observation explosion. **No** CVE correlation. |
| `software_observed` | **Legacy** bounded per-package preview path (**≤128** rows) from older releases; the worker **deletes** these rows on successful package inventory to avoid duplicate evidence. **`upsert_cred_software_observations`** remains in **`daemon/recon_observations.py`** for compatibility/selftests only — **not** the primary inventory store. |
| _(SNMP hostname reuse)_ | **`hostname_observed`** / **`fqdn_observed`** rows above — populated from SNMP **sysName** only when **`snmpv3.device_identity`** succeeds with a usable **sysName**; **`credentialed_check`** provenance distinguishes source (`slice 9`). |
| `device_identity_observed` | **Summarized** SNMP device fingerprint: `normalized_value` is a short digest (`sha256` prefix + vendor enterprise hint); `raw_value` small JSON (bounded **sysObjectID** / **sysName**, flags, `result_id`). **Not** per-OID rows — **no** `snmp_sysobjectid_observed` explosion in MVP slice 9. |

The credentialed check **worker** writes **observation** rows **additively**; it **does not** update **`asset_assertions`** directly.

### Software inventory summary assertion (slice 2)

| Assertion type | Meaning |
|----------------|---------|
| `software_inventory_summary` | **One summary row per asset** (`asserted_value` like `237 packages (dpkg)`). Produced lazily on single-asset `GET` (`api/lib_reconciliation.php` **`st_recon_lazy_reconcile_software_inventory_summary`**). **`assertion_sources`** link **`package_inventory_observed`** (primary when present), **`software_inventory_snapshot_observed`** when present, **active normalized inventory** via snapshot/count semantics, and up to **five** legacy **`software_observed`** samples — never one assertion per package. **Confidence is only freshness/completeness** (`low` \| `medium`); **never** vulnerability exposure or advisory authority. **Stale threshold:** **`ST_RECON_SOFTWARE_INVENTORY_STALE_DAYS` = 90** — evidence older than this is treated as stale (**`low`** confidence with explanation). **`software_inventory_observation_gap`** when **`package_inventory_observed`** lacks **normalized snapshot / active rows / legacy `software_observed`** corroboration. Diagnostics substring **`normalized inventory corroboration is absent`** when relevant. Explanations embed fragments for diagnostics (**`(stale threshold)`**, **`partial, truncated, or capped below total installed package cardinality`**). **Slice 3** adds **`software_inventory_catalog`** (counts + timestamps). **`trusted_data`** adds **`software_inventory_rows_total`** and **`software_inventory_latest_active_last_seen`** (scalar-only). Future inventory sources (**scanner / API integrations / SBOM / agents**) are **fusion-ready in prose/constants only** until explicit ingest ships — reconciliation-first posture intentional; **no CVE fusion**. |

**Slice 10:** lazy **`os_platform`** reconciliation reads the latest **`os_version_observed`** row from recon source **`credentialed_check`** and merges it into the existing resolver:

- **Fresh** authenticated OS release (≤ **90 days** since `observed_at`) is generally **stronger than unauthenticated scan `os_guess` / Zabbix-only hints**: it drives the asserted slug when present, with **higher confidence when scan or Zabbix agrees**, and **medium confidence plus explicit explanation when they conflict** (both sides stay as observations).
- **Stale** authenticated OS release (**> 90 days**, or **missing `observed_at`**) **does not override** newer scan/Zabbix fingerprints; if no other signal exists, belief may fall back to **low** confidence with a stale note.
- **`package_inventory_observed`** remains **summary-only evidence** (shown in host OS evidence list); it does **not** assert software inventory, **CVE fusion**, or findings (deferred).
- **`software_inventory_snapshot_observed`** + **`software_inventory*`** tables hold durable inventory; **slice 2** rolls evidence into **`software_inventory_summary`** without CVE or per-package assertions. Legacy **`software_observed`** may still appear on older databases until the next successful inventory run cleans it up.
- **Shipped (bounded):** **package→advisory** correlation exists for **locally imported** advisories only — see *Local advisory correlation* below. Normalized inventory observations remain **non-authoritative** for vulnerability by themselves; **vendor/internal package rules** (and deterministic version compare) drive **`asset_vulnerabilities`**. Broader fusion (live feeds, KEV, EPSS, SOAR) remains scoped in [Roadmap — Package-advisory correlation (future)](../ROADMAP.md#package-advisory-correlation-future).

**Identity (slice 10):** SNMP **`hostname_observed` / `fqdn_observed`** from **`sysName`** participate in existing **`canonical_hostname`** reconciliation. **SNMP-only** evidence is **scored lower** than corroborated DNS/scan/Zabbix hostname signals; **FQDN + hostname both from the same SNMP sysName parse** does **not** count as full “FQDN corroboration”. When SNMP agrees with other hostname sources, explanations mention it. **`device_identity_observed`** is linked as **supporting context only** (assertion source note); it is **not** a canonical hostname by itself.

Assertions still update **only** through **`api/lib_reconciliation.php`** lazy helpers (never direct worker writes).

---

## Lazy vs write path

- **Write paths** record observations; they **do not** eagerly re-run full reconciliation for every write (keeps ingest fast and predictable).
- **Lazy reconciliation** runs when an operator opens **Host Details** (single-asset `GET` in `assets.php`), so the displayed OS, identity, and **software inventory summary** beliefs are refreshed for that view without changing scanner or Zabbix ingest semantics beyond additive observation rows.

---

## Diagnostics

- **Host modal**: compact OS evidence, **software inventory** summary (`software_inventory_*` fields + bounded preview via **`recon_detail.software_inventory_rows`** with legacy **`recon_detail.software_observed`** fallback), plus **identity** block (`canonical_hostname_*`, `identity_recon_detail` with supporting vs conflicting observation ids where applicable). **`recon_detail` / `identity_recon_detail`** observations include **`contribution_hint`** (how the row ties to the current belief when linked), **`source_object_ref`** (plugin/run ref for cred checks), and **`observed_at`**. When confidence allows, the overview headline may prefer **`trusted_*`** fields while **stored** hostname / scan OS remain in Identity & inventory.
- **Assets list** (`GET /api/assets.php`): each row includes optional **`trusted_*`** fields; search matches canonical hostname / OS assertion slugs in addition to stored columns; hostname sort prefers reconciled short name when confidence is sufficient.
- **Exports** (`/api/export.php`): same additive **`trusted_*`** columns at the end of CSV / in JSON objects.
- **System Health** (`/api/health.php`): read-only `trusted_data` block (table readiness, OS + identity observation/assertion counts, software inventory summary counts above plus **slice 4** readiness metrics **`software_inventory_summary_stale_evidence_90_180d_assets`**, **`software_inventory_summary_stale_evidence_over_180d_assets`**, **`software_inventory_assets_repeat_partial_pkg_inventory`**, **`software_inventory_summary_reconciled_after_sw_obs_assets`**, **`software_inventory_summary_without_bounded_sw_obs_assets`** (now treats missing normalized corroboration like missing legacy rows), **`software_inventory_rows_total`**, **`software_inventory_latest_active_last_seen`** — appended only when non-zero alongside legacy **`software_inventory_summary_*`** fields), approximate hostname-conflict asset count, recent lazy reconciliation failures for OS/identity slices, stale OS assertion hint, **`credentialed_observation_count`**, **`stale_cred_os_observations_90d`** when tables exist — surfaced quietly when cred observations exist). **`trusted_data` stays numeric/count-oriented** (contract-tested — no raw package arrays). Additive **`vulnerability_correlation`** block (when tables exist) reports advisory counts, affected-row/asset counts, queued correlation jobs, stale-advisory hint, and last correlation run duration — **counts only**.
- **Admin** (`/api/recon_diagnostics.php?asset_id=…`): OS payload in `recon`, identity payload in `identity_recon`, and read-only **`software_inventory`** summary diagnostics (no assertion write); optional `include_sources=1`. POST `action=trim_runs` (with CSRF) trims old `reconciliation_runs` rows—see library helper `st_recon_trim_reconciliation_runs`.

---

## Retention

`reconciliation_runs` can grow without bound as assets are viewed and reconciled. Operators may trim via the admin diagnostics endpoint; adjust `keep` to retain more or fewer newest rows. This is intentionally simple—no background retention scheduler in this slice.

**`software_inventory*`** asset state is **long-lived**: inactive rows record “last seen” history; **do not** bulk-delete active/inactive state as part of routine observation pruning. **`asset_vulnerabilities`** correlated rows are **long-lived** as well (do not bulk-prune active exposure state as part of routine observation pruning). **`asset_vulnerability_triage`**, **`vulnerability_notes`**, and **`vulnerability_activity_log`** hold operator workflow and audit history — **no hard deletes** of correlated exposure rows when suppressing or accepting risk; use **`scripts/prune_vulnerability_activity.php`** (dry-run by default) to trim **old activity log rows only** after operational policy. **`software_observed`** (legacy) is removed on new inventories. Historical bounded snapshots remain in **`credential_check_results`** / artifacts — prune per operational retention when disk grows.

**Exception (test/internal advisories):** **`scripts/remove_advisory.php`** intentionally **`DELETE`s** a single **`vulnerability_advisories`** row (dry-run by default; **`--apply`** required). SQLite FK cascades remove **`vulnerability_advisory_packages`**, matching **`asset_vulnerabilities`**, and therefore triage/notes/activity for those rows. Use only for **lab keys** (`CVE-TEST-*`), **`internal`/`sample`**, or **`nvd`+`metadata_only`**, or after **`--force`** review — not as routine suppression. See [wiki — Vulnerability advisory operator runbook](wiki/vulnerability-advisory-runbook.md).

---

## Local advisory correlation (inventory-driven)

**Tables:** `vulnerability_advisories` (canonical `advisory_key` + metadata + **`references_json`** optional + **`package_authority`**), `vulnerability_advisory_packages` (ecosystem + `normalized_name` + version rule or `fixed_version` + optional `distro_release`), `asset_vulnerabilities` (join `software_inventory_asset_state` ↔ advisory, `status` = `affected` \| `fixed` \| `ignored`), `vulnerability_correlation_runs` (bounded batch telemetry).

### `package_authority` (precedence)

| Value | Meaning |
|-------|---------|
| **`metadata_only`** | CVE metadata carrier (description, CVSS, severity, dates, **`references_json`**). **Does not** participate in package correlation — NVD-only rows **never** prove an installed package is affected, even if stray package rules exist. |
| **`vendor_distro`** | Distro/vendor advisory truth (Ubuntu/Debian/Red Hat/Alpine importers or merged precedence). Drives **`asset_vulnerabilities`** when rules match. |
| **`internal`** | Operator `internal` / `sample` imports, or explicit package rules on an NVD key (treated as policy, not distro authority). Drives correlation. |

On upsert, authority and **`source`** merge so **vendor > internal > metadata_only** for the same `advisory_key` (see `api/lib_vulnerability_advisory_import.php`).

### Ingestion (bounded CLIs)

- **`php scripts/import_advisories.php`** — general `advisories[]` JSON (packages optional).
- **`php scripts/import_nvd_metadata.php`** — `vulnerabilities[]` JSON file → **`metadata_only`**; leaves existing package rules from other feeds intact on merge.
- **`php scripts/import_nvd_from_local_db.php --apply`** — **NVD bridge**: reads existing `data/nvd.db` (populated by `daemon/sync_nvd.py`) and imports CVE metadata into `vulnerability_advisories` as **`metadata_only`**. Does not write package rules or create affected assets. Supports `--incremental`, `--since=YYYY-MM-DD`, `--limit=N`. Dry-run default.
- **`php scripts/import_distro_advisories.php`** — `distro_source` `ubuntu` \| `debian`; **`distro_release`** required per advisory; emits dpkg **`fixed_version`** rules.

All are transactional, offline, and reject oversized inputs (see script headers).

### Matching and explainability

Deterministic **`dpkg` / `rpm` / `generic`** ordering in `api/lib_version_compare.php`. When **`fixed_version`** is set, a host is **affected** iff installed version is **strictly below** that fix (Debian-style); **`distro_release`** must match the inventory row when the rule specifies it. Otherwise operators use `version_operator` (`=`, `<`, `<=`, `>`, `>=`) against `version_value`. **`asset_vulnerabilities.explain_json`** records structured rationale including **`correlation_basis_label`** (“Vendor advisory match”, “Internal advisory match”, or “NVD metadata only” for context fields) and **`correlation_confidence`** (**`high`** for vendor matches, **`medium`** for internal policy matches in the current policy).

**Lifecycle:** `php scripts/run_vulnerability_correlation.php` (batch or `--consume-jobs`) refreshes matches; rows no longer matching become **`fixed`** with `fixed_detected_at`. **`ignored`** is preserved on upsert. **Retention:** do not bulk-prune active `asset_vulnerabilities`; correlation run history may be trimmed later.

**UI/API:** single-asset `GET /api/assets.php?id=` includes bounded **`vulnerability_inventory`** (counts + first page; triage-aware fields include **basis** + **correlation confidence**). Additional reads: `GET /api/vulnerabilities.php` (`list_for_asset`, `assets_for_advisory`, `advisory_detail`, `top_packages`). **Health:** `vulnerability_correlation` block adds per-source advisory counts, **`package_authority`** histogram, vendor vs internal package-rule counts, **`advisory_package_rules_by_ecosystem_release`**, and last-import hints by `source` (see `api/lib_vulnerability_correlation.php` **`st_vuln_correlation_health_snapshot`**).

### Vulnerability triage, prioritization, and analyst workflow

**Tables:** `asset_vulnerability_triage` (one row per `asset_vulnerabilities.id`: `triage_state`, **`priority`** = stored triage band shown in dashboards, **`priority_source`** = `model` \| `analyst_override`, assignment, suppression reason/expiry, `notes_count`), `vulnerability_notes` (plain text, **≤8000** characters; control characters stripped), `vulnerability_activity_log` (append-only audit; `details_json` is **allowlisted keys only**). APIs and **`vulnerability_inventory`** rows expose **`model_priority`**, **`model_priority_score`**, **`model_priority_rationale`**, **`triage_priority`** (same as stored `priority`), and **`priority_source`** so clients can distinguish deterministic model output from analyst-chosen bands.

**Prioritization:** `api/lib_vulnerability_priority.php` computes a **deterministic** integer score and band (`critical` … `info`) from advisory severity, CVSS, age since `first_seen_at`, optional future placeholders (internet exposure, KEV), triage posture, **active** temporary suppression (expiry strictly in the future), and correlation `fixed` status. Output includes a **rationale** array (explainable steps; no ML).

**Suppression:** Temporary holds use `suppression_reason` + `suppression_expires_at`. Expired suppressions are **cleared** by `st_vt_sweep_expired_suppressions()` (invoked at the start of each per-asset correlation run) and emit **`suppression_expired`** activity; correlation rows stay **`affected`** until the inventory no longer matches. **`false_positive`** / **`accepted_risk`** are triage states (terminal score posture), not row deletes.

**Correlation interaction:** Re-correlation **preserves** triage, notes, and activity history; new matches **ensure** a triage row via `INSERT OR IGNORE`. Marking **`fixed`** logs **`correlation_mark_fixed`** and caps operational priority in the model.

**Stored vs computed priority:** `asset_vulnerability_triage.priority` is kept aligned with `st_vt_compute_priority_for_row()` via **`st_vt_resync_priority_column()`** (bounded batch or single `asset_vulnerability_id`; optional dry-run via the fourth `apply` argument). Resync runs after correlation upserts, after suppression expiry sweep entries, after suppress/unsuppress, and after **`update_state`** when the client did **not** send an explicit `priority` override (operator-provided priority is left as-is until the next correlation or a manual **`scripts/resync_vulnerability_triage_priority.php --apply`** pass).

**API:** `GET/POST /api/vulnerability_triage.php` — allowlisted actions, bounded pagination, CSRF on mutations, **`scan_editor`/`admin`** for writes. **Views** (`list_view`): top vulnerable assets, highest triage priority, aging, suppressed, by severity, by ecosystem — all **capped** row limits.

**Ops:** `php scripts/diagnose_vulnerability_triage.php` (read-only JSON bundle; includes **`triage_priority_mismatch_count`** / **`oldest_priority_mismatch_at`** over a bounded scan). **`scripts/resync_vulnerability_triage_priority.php`** — dry-run by default, **`--apply`** to write; **`--limit`**, **`--asset-vulnerability-id`**, optional **`--db=`**. **`scripts/st_vulnerability_triage_selftest.php`** exercises transitions, suppression expiry, notes, activity, correlation coexistence, and priority resync.

**Post-inventory:** after successful normalized package persist, the cred worker **best-effort enqueues** one `vulnerability_correlation` job per asset (deduped); heavy work stays in offline scripts/cron — **not** inline in the scan path.

### Vulnerability Dashboard (operator risk posture)

**API:** `GET /api/vulnerability_dashboard.php` — read-only, allowlisted actions (`summary`, `top_assets`, `recent_findings`, `aging`, `by_severity`, `by_package`, `by_advisory`, `suppressed`, `overrides`). All queries bounded with explicit `LIMIT` caps (top assets ≤100, recent findings ≤250, package/advisory summaries ≤100). No raw artifact access, no secrets, safe sort allowlists, pagination via `offset`.

**Risk rollup:** `st_vuln_asset_risk_rollup(PDO, int $assetId)` computes per-asset weighted score: critical=40, high=10, medium=3, low=1, info=0. Bands: ≥80 critical, ≥30 high, ≥10 medium, ≥1 low, 0 none. Includes suppressed/override counts and oldest open `first_seen_at`.

**Summary:** global counts (total open, by severity, by triage priority), distinct affected assets, oldest finding, stale findings >30 days, active suppressions, analyst overrides.

**UI:** dedicated "Vuln Dashboard" tab with summary cards, highest-risk assets table, aging criticals, most common vulnerable packages, recent findings (paginated), suppressed findings, and analyst overrides. Asset detail host panel includes a risk rollup banner when correlated findings exist.

**Health:** `vulnerability_dashboard` block in `/api/health.php` reports `total_open_findings`, `critical_open_findings`, `stale_findings_over_30d`, `suppressed_active`, `override_active`, `top_risk_asset_id`, and `warnings[]` (stale correlation, no advisories, aging criticals, triage mismatches).

**Diagnostics:** `php scripts/diagnose_vulnerability_dashboard.php [--db=]` — JSON output: summary, top-10 assets, advisory ingestion freshness, stale warnings, triage mismatch, health snapshot.

**Selftest:** `php scripts/st_vulnerability_dashboard_selftest.php` — validates rollup math, suppression/override counts, aging logic, risk bands, bounded query limits, summary and health snapshot shapes.

**Constraints:** SQLite-safe, offline, no charting libraries, no unbounded auto-refresh, no external APIs, no websocket streaming.

---

## Related code

- `api/lib_reconciliation.php` — reconciliation, health snapshot, evidence detail, trim helper
- `api/assets.php` — lazy OS + identity reconcile; `recon_detail` + `identity_recon_detail` on single-asset GET; operator hostname `PUT` writes identity observations; additive **`vulnerability_inventory`** on single-asset GET when tables exist
- `daemon/recon_observations.py` — scan-side identity observation writes; cred-check **`os_version_observed`**, **`package_inventory_observed`**, **`software_inventory_snapshot_observed`**, legacy **`software_observed`** cleanup helpers, SNMP **`hostname_observed`** / **`fqdn_observed`**, **`device_identity_observed`** upserts + `credentialed_check` source seed
- `daemon/software_inventory_normalize.py`, `daemon/software_inventory_persist.py` — normalized inventory writes from **`daemon/cred_check_run.py`**
- `daemon/vuln_correlation_jobs.py` — enqueue deduped **`worker_jobs`** (`vulnerability_correlation`) after inventory persist
- `api/lib_software_inventory.php`, `api/software_inventory.php` — bounded read/search API
- `api/lib_version_compare.php`, `api/lib_vulnerability_priority.php`, `api/lib_vulnerability_advisory_import.php`, `api/lib_vulnerability_correlation.php`, `api/lib_vulnerability_triage.php`, `api/vulnerabilities.php`, `api/vulnerability_triage.php` — **local advisory correlation** plus **bounded analyst triage** (inventory → rules → `asset_vulnerabilities`); **not** scanner findings, NVD live mirror, automated remediation, ticketing, or SOAR
- `scripts/import_advisories.php`, `scripts/import_nvd_metadata.php`, `scripts/import_nvd_from_local_db.php`, `scripts/import_distro_advisories.php`, `scripts/remove_advisory.php`, `scripts/run_vulnerability_correlation.php`, `scripts/diagnose_vulnerability_correlation.php`, `scripts/st_vulnerability_correlation_selftest.php`, `scripts/st_remove_advisory_selftest.php` — bounded import, NVD bridge, offline correlation, diagnostics, selftests
- `scripts/diagnose_vulnerability_triage.php`, `scripts/prune_vulnerability_activity.php`, `scripts/resync_vulnerability_triage_priority.php`, `scripts/st_vulnerability_triage_selftest.php` — triage diagnostics, optional **activity-log-only** retention prune (dry-run default), **priority resync** CLI (dry-run default), triage selftest
- `api/vulnerability_dashboard.php`, `scripts/diagnose_vulnerability_dashboard.php`, `scripts/st_vulnerability_dashboard_selftest.php` — operator vulnerability dashboard API, diagnostics, selftest
- `docs/samples/*.json` — shipped bounded sample payloads for importer validation (mirrors `data/samples/` in git)
- `scripts/st_recon_trusted_data_selftest.php` — no-network checks for cred-aware OS + SNMP hostname reconciliation wording (slice 10)
- `daemon/st_software_observation_selftest.py` — normalization, dedupe, cap, replace semantics for **`software_observed`**
- `scripts/st_software_inventory_summary_selftest.php` — resolver rules for **`software_inventory_summary`** (fresh/partial/stale, CVE disclaimer text)
- `scripts/st_software_inventory_evidence_selftest.php` — single-asset software field contract + bounded `recon_detail` shape (no full package list)
- `scripts/st_software_inventory_diagnostics_selftest.php` — stale bands + health `trusted_data` leak guards
- `daemon/credential_check_worker.py` / `daemon/cred_check_run.py` — slice 7–9 observation writes (no assertion SQL)
- `api/health.php` — `trusted_data`, `operational_integrity`
- `api/recon_diagnostics.php` — admin asset diagnostics and optional trim
- `scripts/run_operational_integrity_suite.php` — unified read-only validation (selftests, DB, runtime, deploy, health)
- `scripts/check_database_integrity.php` — standalone database consistency checker (orphans, duplicates, stale leases, FK integrity)
- `scripts/st_operational_integrity_selftest.php` — in-memory lifecycle regression (import→correlate→triage→suppress→cleanup→assert)
- `scripts/diagnose_operational_integrity.php` — JSON diagnostic output (scheduler, worker, vulnerability, DB state)
- `api/vulnerability_remediation.php` — CRUD + verify + close for remediation actions (CSRF on POST, bounded, audit-logged)
- `scripts/st_vulnerability_remediation_selftest.php` — lifecycle, verification, overdue, prune, orphan, cascade tests
- `scripts/diagnose_vulnerability_remediation.php` — JSON: overdue, verification failures, stale actions, orphans
- `scripts/prune_vulnerability_remediation_history.php` — dry-run default retention prune (closed+verified, >90d)
