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
| `software_observed` | **Bounded** per-package **identity preview** from **`ssh.linux.package_inventory@1.0.0`** only (`daemon/recon_observations.py` **`upsert_cred_software_observations`**). At most **128** deduped `(normalized_name, version, manager)` rows **per asset** for this plugin: each successful inventory **replaces** prior `software_observed` rows scoped to the same `plugin_key` (latest run wins). `raw_value` is small JSON (`name`, `normalized_name`, `version`, `manager`, `source`, `partial`). **No** semantic versioning, **no** CPE, **no** vendor inference, **no per-package assertions**, **no** CVE correlation. **Slice 2** consumes observations plus **`package_inventory_observed`** for a single **`software_inventory_summary`** assertion (below). Aggregate counts remain on **`package_inventory_observed`** and **`credential_check_results`**. API/UI: **`evidence_summary.software_observation_count`** and up to **3** preview labels — **no** full package dump in the UI. |
| _(SNMP hostname reuse)_ | **`hostname_observed`** / **`fqdn_observed`** rows above — populated from SNMP **sysName** only when **`snmpv3.device_identity`** succeeds with a usable **sysName**; **`credentialed_check`** provenance distinguishes source (`slice 9`). |
| `device_identity_observed` | **Summarized** SNMP device fingerprint: `normalized_value` is a short digest (`sha256` prefix + vendor enterprise hint); `raw_value` small JSON (bounded **sysObjectID** / **sysName**, flags, `result_id`). **Not** per-OID rows — **no** `snmp_sysobjectid_observed` explosion in MVP slice 9. |

The credentialed check **worker** writes **observation** rows **additively**; it **does not** update **`asset_assertions`** directly.

### Software inventory summary assertion (slice 2)

| Assertion type | Meaning |
|----------------|---------|
| `software_inventory_summary` | **One summary row per asset** (`asserted_value` like `237 packages (dpkg)`). Produced lazily on single-asset `GET` (`api/lib_reconciliation.php` **`st_recon_lazy_reconcile_software_inventory_summary`**). **`assertion_sources`** link **`package_inventory_observed`** (primary when present) plus up to **five** **`software_observed`** samples — never one assertion per package. **Confidence is only freshness/completeness** (`low` \| `medium`); **never** vulnerability exposure or advisory authority. **Stale threshold:** **`ST_RECON_SOFTWARE_INVENTORY_STALE_DAYS` = 90** — evidence older than this is treated as stale (**`low`** confidence with explanation). **Slice 4** adds explicit **`medium`**/**`low`** rationale sentences, **`software_inventory_stale_band`** (`fresh` \| `90_180` \| `over_180`), **`software_inventory_observation_gap`** when **`package_inventory_observed`** lacks **`software_observed`** corroboration (operator diagnostics — **not** a CVE signal), and stable substring **`bounded software_observed corroboration is absent`** when relevant. Explanations embed fragments for diagnostics (**`(stale threshold)`**, **`partial, truncated, or capped below total installed package cardinality`**). **Slice 3** UX fields (**`software_inventory_stale`**, **`software_inventory_source`**, **`recon_diagnostics.software_inventory`**) remain; **full package dumps stay off default JSON**. Additional **`trusted_data`** readiness counters (stale age splits, repeat partial inventories, reconciliation drift hints) are **scalar-only**. Future inventory sources (**scanner / API integrations / SBOM / agents**) are **fusion-ready in prose/constants only** until explicit ingest ships — reconciliation-first posture intentional; **no CVE fusion**. |

**Slice 10:** lazy **`os_platform`** reconciliation reads the latest **`os_version_observed`** row from recon source **`credentialed_check`** and merges it into the existing resolver:

- **Fresh** authenticated OS release (≤ **90 days** since `observed_at`) is generally **stronger than unauthenticated scan `os_guess` / Zabbix-only hints**: it drives the asserted slug when present, with **higher confidence when scan or Zabbix agrees**, and **medium confidence plus explicit explanation when they conflict** (both sides stay as observations).
- **Stale** authenticated OS release (**> 90 days**, or **missing `observed_at`**) **does not override** newer scan/Zabbix fingerprints; if no other signal exists, belief may fall back to **low** confidence with a stale note.
- **`package_inventory_observed`** remains **summary-only evidence** (shown in host OS evidence list); it does **not** assert software inventory, **CVE fusion**, or findings (deferred).
- **`software_observed`** adds a **capped** identity preview; **slice 2** rolls it up into **`software_inventory_summary`** without CVE or per-package assertions.
- **Future:** possible **package→advisory** correlation (feeds, identity, confidence, evidence) is scoped and constrained in [Roadmap — Package-advisory correlation (future)](../ROADMAP.md#package-advisory-correlation-future); inventory observations remain **non-authoritative** for vulnerability until that track ships with explicit governance.

**Identity (slice 10):** SNMP **`hostname_observed` / `fqdn_observed`** from **`sysName`** participate in existing **`canonical_hostname`** reconciliation. **SNMP-only** evidence is **scored lower** than corroborated DNS/scan/Zabbix hostname signals; **FQDN + hostname both from the same SNMP sysName parse** does **not** count as full “FQDN corroboration”. When SNMP agrees with other hostname sources, explanations mention it. **`device_identity_observed`** is linked as **supporting context only** (assertion source note); it is **not** a canonical hostname by itself.

Assertions still update **only** through **`api/lib_reconciliation.php`** lazy helpers (never direct worker writes).

---

## Lazy vs write path

- **Write paths** record observations; they **do not** eagerly re-run full reconciliation for every write (keeps ingest fast and predictable).
- **Lazy reconciliation** runs when an operator opens **Host Details** (single-asset `GET` in `assets.php`), so the displayed OS, identity, and **software inventory summary** beliefs are refreshed for that view without changing scanner or Zabbix ingest semantics beyond additive observation rows.

---

## Diagnostics

- **Host modal**: compact OS evidence, **software inventory** summary (`software_inventory_*` fields + bounded preview via **`recon_detail.software_observed`**), plus **identity** block (`canonical_hostname_*`, `identity_recon_detail` with supporting vs conflicting observation ids where applicable). **`recon_detail` / `identity_recon_detail`** observations include **`contribution_hint`** (how the row ties to the current belief when linked), **`source_object_ref`** (plugin/run ref for cred checks), and **`observed_at`**. When confidence allows, the overview headline may prefer **`trusted_*`** fields while **stored** hostname / scan OS remain in Identity & inventory.
- **Assets list** (`GET /api/assets.php`): each row includes optional **`trusted_*`** fields; search matches canonical hostname / OS assertion slugs in addition to stored columns; hostname sort prefers reconciled short name when confidence is sufficient.
- **Exports** (`/api/export.php`): same additive **`trusted_*`** columns at the end of CSV / in JSON objects.
- **System Health** (`/api/health.php`): read-only `trusted_data` block (table readiness, OS + identity observation/assertion counts, software inventory summary counts above plus **slice 4** readiness metrics **`software_inventory_summary_stale_evidence_90_180d_assets`**, **`software_inventory_summary_stale_evidence_over_180d_assets`**, **`software_inventory_assets_repeat_partial_pkg_inventory`**, **`software_inventory_summary_reconciled_after_sw_obs_assets`**, **`software_inventory_summary_without_bounded_sw_obs_assets`** — appended only when non-zero alongside legacy **`software_inventory_summary_*`** fields), approximate hostname-conflict asset count, recent lazy reconciliation failures for OS/identity slices, stale OS assertion hint, **`credentialed_observation_count`**, **`stale_cred_os_observations_90d`** when tables exist — surfaced quietly when cred observations exist). **`trusted_data` stays numeric/count-oriented** (contract-tested — no raw package arrays).
- **Admin** (`/api/recon_diagnostics.php?asset_id=…`): OS payload in `recon`, identity payload in `identity_recon`, and read-only **`software_inventory`** summary diagnostics (no assertion write); optional `include_sources=1`. POST `action=trim_runs` (with CSRF) trims old `reconciliation_runs` rows—see library helper `st_recon_trim_reconciliation_runs`.

---

## Retention

`reconciliation_runs` can grow without bound as assets are viewed and reconciled. Operators may trim via the admin diagnostics endpoint; adjust `keep` to retain more or fewer newest rows. This is intentionally simple—no background retention scheduler in this slice.

**`software_observed`:** bounded by **design** (≤128 rows per asset per package-inventory plugin path). Rows are **replaced** when a new inventory succeeds; stale rows do **not** accumulate per package across runs. Historical truth for large inventories remains in **`credential_check_results`** (bounded `normalized_json`) and artifacts — prune those tables using operational retention guidance when disk grows.

---

## Related code

- `api/lib_reconciliation.php` — reconciliation, health snapshot, evidence detail, trim helper
- `api/assets.php` — lazy OS + identity reconcile; `recon_detail` + `identity_recon_detail` on single-asset GET; operator hostname `PUT` writes identity observations
- `daemon/recon_observations.py` — scan-side identity observation writes; cred-check **`os_version_observed`**, **`package_inventory_observed`**, **`software_observed`** (bounded package identities), SNMP **`hostname_observed`** / **`fqdn_observed`**, **`device_identity_observed`** upserts + `credentialed_check` source seed
- `scripts/st_recon_trusted_data_selftest.php` — no-network checks for cred-aware OS + SNMP hostname reconciliation wording (slice 10)
- `daemon/st_software_observation_selftest.py` — normalization, dedupe, cap, replace semantics for **`software_observed`**
- `scripts/st_software_inventory_summary_selftest.php` — resolver rules for **`software_inventory_summary`** (fresh/partial/stale, CVE disclaimer text)
- `scripts/st_software_inventory_evidence_selftest.php` — single-asset software field contract + bounded `recon_detail` shape (no full package list)
- `scripts/st_software_inventory_diagnostics_selftest.php` — stale bands + health `trusted_data` leak guards
- `daemon/credential_check_worker.py` / `daemon/cred_check_run.py` — slice 7–9 observation writes (no assertion SQL)
- `api/health.php` — `trusted_data`
- `api/recon_diagnostics.php` — admin asset diagnostics and optional trim
