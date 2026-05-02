# SurveyTrace Handoff Summary (2026-05-01)

Use this as a context starter in a new conversation.

**Release:** **0.12.0** (semver in repo-root **`VERSION`**; PHP **`ST_VERSION`** via **`api/st_version.php`**) — **Phase 12** asset lifecycle: coverage-based **`active` / `stale` / `retired`** on **`assets`** (**`migration_phase12_asset_lifecycle_v1`** in **`api/db.php`**), **`daemon/asset_lifecycle.py`**, **`scanner_daemon.py`**, **`collector_ingest_worker.py`**, **`change_detection.py`** alert types **`asset_stale`**, **`asset_retired`**, **`asset_reactivated`**. Operator columns **`owner`**, **`business_unit`**, **`criticality`**, **`environment`**, **`identity_confidence`**, **`identity_confidence_reason`**. **`api/assets.php`** filter + **`api/export.php`** extended columns; **`deploy.sh`** / **`setup.sh`** WAL sidecar handling + PHP migration bootstrap on deploy. Prior: **0.11.0** Phases **10–11** triage + **`cve_intel`**; **0.9.0** Phase **9** change detection.

**Roadmap numbering:** README **Roadmap** phases **9–12** match SQLite **`migration_phase9_*` … `migration_phase12_*`** in **`api/db.php`**. **Upcoming** starts at **Phase 13** (baselines).

## Where things stand

- **Phase 8 (collectors)** — MVP is in-tree: registration/check-in, job lease/submit, ingest worker path, `collector/` packaging, UI overview + Settings, schedule `collector_id`, CIDR guardrails. Treat operational hardening (ingest scale, token rotation UX, more tests) as follow-on, not “not started.”
- **Phases 1–7** — Delivered in practical scope (profiles, queue/scheduling, discovery, device identity, access hardening, scan trash/retention). Phase 5 optional follow-ons remain deferred unless needed.
- **Phases 9–12** — Delivered: change alerts + finding lifecycle (**9**), explainable triage (**10**), **`cve_intel`** + sync (**11**), asset lifecycle + export/deploy wiring (**12**).
- **Roadmap detail** — See **`README.md`** for **Phase 13+** (baselines, integrations program, UI polish, credentialed checks, governance).

## Session updates (2026-05-01)

- **0.12.0** — **`VERSION`** / **`st_version.php`** / **`surveytrace_version.py`**; **`api/db.php`** **`st_migrate_phase12_asset_lifecycle_v1`**; **`daemon/asset_lifecycle.py`**; **`deploy.sh`** (copy **`asset_lifecycle.py`**, WAL **`surveytrace.db-wal`/`-shm`** ownership, **`php` `st_db()`** bootstrap as **www-data**); **`collector/deploy.sh`** includes **`asset_lifecycle.py`**; **`setup.sh`** WAL sidecar fix; **`api/export.php`** Phase 12 columns; **`README.md`**, **`RELEASE_NOTES.md`**, roadmap **9–12** completed block.
- **0.11.0** (same day, prior tag) — Phases **10–11** triage + **`cve_intel`** + **`sync_cve_intel.py`**; **`deploy.sh`** ships **`sync_cve_intel.py`**; fingerprint/WebFP hypervisor tuning.
- **0.8.2** — **`profiles.py`** / **`scanner_daemon.py`** full-TCP phase validation and **`fast_full_tcp`** intensity/routed behavior.

## Session updates (2026-04-30)

- **Collector install token** — UI generate-only; **`api/settings.php`** rejects raw `collector_install_token` in POST.
- **Collector overview** — **`api/collectors.php`** **`online_recent_2m`**; **Set ranges** modal.
- **Fingerprinting** — **`daemon/fingerprint.py`**: Linux + xrdp vs RDP port profile.

## Next suggested steps

1. **CVE intel ops** — run **`sync_cve_intel.py`** where outbound to CISA / FIRST / OSV is allowed.
2. **WebFP refresh** — **`sync_webfp.py`** after upgrades for **`hv`** overrides.
3. **Phase 13+** — baselines/reporting per **`README.md`**.

## Important files (recent touchpoints)

- **`VERSION`**, **`api/st_version.php`**, **`daemon/surveytrace_version.py`**
- **`api/db.php`** — migrations through **`st_migrate_phase12_asset_lifecycle_v1`**
- **`daemon/asset_lifecycle.py`**, **`daemon/change_detection.py`**, **`daemon/scanner_daemon.py`**, **`daemon/collector_ingest_worker.py`**
- **`api/assets.php`**, **`api/export.php`**, **`sql/schema.sql`**
- **`deploy.sh`**, **`setup.sh`**, **`collector/deploy.sh`**
- **`README.md`**, **`RELEASE_NOTES.md`**
