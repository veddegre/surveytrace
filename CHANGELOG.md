# Changelog

All notable changes to this project will be documented in this file.

Canonical app version is the single line in `VERSION` at the install root.
Published release summaries are also tracked in `RELEASE_NOTES.md`.

## [Unreleased]

### Added

### Changed

### Fixed

### Removed

## [1.0.2] - 2026-05-07

Operational lifecycle and maintenance milestone completion release: manual maintenance tooling, admin read-only visibility, backup/restore readiness validation, and runbook hardening. No new execution transports or automated maintenance schedulers.

### Added

- Operational maintenance CLI utilities:
  - `scripts/rewrap_credential_secrets.php`
  - `scripts/prune_operational_history.php`
  - `scripts/recover_stale_worker_jobs.php`
  - `scripts/validate_backup_restore_readiness.php`
- Maintenance selftests:
  - `scripts/st_cred_secret_rewrap_selftest.php`
  - `scripts/st_operational_prune_selftest.php`
  - `scripts/st_stale_worker_recovery_selftest.php`
  - `scripts/st_backup_restore_readiness_selftest.php`
- Admin read-only maintenance visibility in health/settings for stale-state and growth signals.

### Changed

- Operational lifecycle docs/runbooks now include:
  - monthly and pre-release maintenance checklists
  - backup/restore required set and restore ordering
  - explicit key-loss and multi-node key parity guidance
- Release readiness checklist expanded for maintenance dry-runs and backup/restore readiness validation.

### Fixed

- Credential secret envelope hardening and decrypt-path safety updates carried through milestone slices (ctxh rewrap path, safer failure signaling, dependency classification clarity).

### Removed

- None.

## [1.0.1] - 2026-05-06

Stabilization and maintenance release: polish, trusted-data foundations, collector ingest clarity, deployment parity, and documentation. **No new credentialed-check execution product** — design docs only.

### Added

- **Trusted data (documentation)** — [docs/TRUSTED_DATA_MODEL.md](docs/TRUSTED_DATA_MODEL.md): observations, assertions, operational display, diagnostics.
- **Credentialed checks (design only)** — [docs/CREDENTIALED_CHECKS_ENGINE.md](docs/CREDENTIALED_CHECKS_ENGINE.md), [docs/CREDENTIALED_CHECKS_MVP_PLAN.md](docs/CREDENTIALED_CHECKS_MVP_PLAN.md): execution model, MVP slices, deferred scope.
- **Release process** — [docs/RELEASE_READINESS_CHECKLIST.md](docs/RELEASE_READINESS_CHECKLIST.md) for pre-tag verification.
- **Runtime (trusted data)** — `api/lib_reconciliation.php`, `api/recon_diagnostics.php`, `daemon/recon_observations.py` (scan-side observation writes); reconciliation-aware list/export/reporting paths as shipped in this line.

### Changed

- **UI / workspace** — Continued visual evolution, host details modal polish, scroll and layout refinements.
- **Light mode** — Tonal refinement for readability on tables, cards, and modals.
- **Collector ingest** — Hardened transitions and clearer **master UI** visibility when collector results are submitted, retried, or failed (operator diagnostics).
- **Trusted operational display** — Prefer reconciled hostname/OS in low-risk read paths where confidence is sufficient; raw fields and evidence remain visible ([TRUSTED_DATA_MODEL.md](docs/TRUSTED_DATA_MODEL.md)).
- **Wiki / operator docs** — Cross-links for trusted data, release readiness, and collector ingest troubleshooting.

### Fixed

- **Deploy / setup** — `deploy.sh` explicit `API_FILES` and daemon lists now include `lib_reconciliation.php`, `recon_diagnostics.php`, `recon_observations.py`; **`docs/`** tree copied on deploy; post-install and post-deploy checks and `php -l` / `py_compile` validation for those paths (`setup.sh`, `deploy.sh`).

## [1.0.0] - 2026-05-05

### Added
- Initial stable release of SurveyTrace
- Dashboard mode and navigation redesign
- Host details modal redesign
- Reports and Enrichment UX improvements
- Zabbix integration status visibility
- Table and UI consistency system

### Changed
- Improved role-based UI behavior (viewer vs scan_editor/admin)
- Refined scope model (job scope vs inventory scope)
- Simplified navigation and header actions
- Unified form controls and table styling
- **Ops — Master `api/` permissions** — `setup.sh` / `deploy.sh` set `/opt/surveytrace/api` to `surveytrace:www-data` with dirs `2750` and files `640` so `surveytrace-scheduler` can read `zabbix_*_worker.php` and other CLI workers; `deploy.sh` ships `zabbix_output_worker.php` and post-deploy checks assert `surveytrace` and `www-data` can read the Zabbix worker scripts.
- **Scheduled Zabbix pull** — Optional `sync_schedule_enabled` / `sync_interval_minutes` / `next_sync_at` on `zabbix_connector`; `daemon/scheduler_daemon.py` spawns `api/zabbix_sync_worker.php` when due; `POST /api/zabbix.php` `save_sync_schedule`; Integrations + Enrichment freshness (`st_zabbix_freshness`, interval-based `fresh` / `stale` / `outdated`); `last_sync_started_at` / `last_sync_completed_at`; manual **Sync now** uses `scheduled_sync_lock` to avoid overlapping pulls. Scheduled pull does not auto-apply scope or identity.
- **Manual scan scopes** — `assets.scope_id` can be set from the Assets tab (bulk **Set scope** / **Clear scope**) and Host detail (**Change scope**), or managed from the Scopes tab (create / rename / delete). `GET /api/scopes.php` includes per-scope asset counts and (for scan editors+) `job_counts` / `schedule_counts`; `GET /api/scopes.php?action=delete_impact&scope_id=N` shows reference counts before delete. `POST /api/scopes.php` supports `action=create|rename|delete` (including clearing references and cascading baseline cleanup). `POST /api/assets.php?action=set_scope_bulk` applies manual changes with `confirm: true` and skips unchanged rows. Audit events include `scope.created`, `scope.renamed`, `scope.deleted`, `scope.assets_assigned`, and `scope.assets_cleared`.
- **Documentation updates** — README cleanup with named tracks and clearer deferred connector notes; added `docs/CONNECTOR_DEVELOPMENT_GUIDE.md`.

### Fixed
- Permission visibility issues in vulnerabilities and scan actions
- Sidebar behavior in collapsed/dashboard mode
- Reporting inconsistencies for scoped data

## [0.16.0]

### Added
- **Splunk starter** — `integrations/starter/splunk_surveytrace/`: `bin/surveytrace_events.py`, `default/inputs.conf`, `default/surveytrace_pull.ini.example`, nav + overview dashboard XML; README for `local/surveytrace_pull.ini` and checkpointing.

### Changed
- **Integrations vs Zabbix scope** — `VERSION` 0.16.0 is primarily an integrations follow-up (UI + legacy config cleanup), distinct from the separately shipped Zabbix monitoring connector work. A SQLite migration in `api/db.php` removes the legacy global pull-token config key when present; it does not by itself imply every future monitoring feature is complete.
- **Integrations UX** — Admin Integrations tab: Push vs Pull / API sections, friendly type labels, type-aware add/edit (modal), quick-start guidance (Grafana Infinity, Prometheus/Alloy, Splunk HEC, Splunk scripted input), per-row token reveal messaging.
- **Pull auth** — Removed unused legacy global pull token (`config.integrations_pull_token_bcrypt`); pull endpoints accept only per-integration bearer tokens of the correct enabled type (`401` / `503` semantics unchanged intent). `api/db.php` applies a migration that deletes the old config key if present.
- **API** — `GET /api/integrations.php` drops legacy global status fields; list rows add `type_label`, `mode`, `destination_summary`. `POST rotate_pull_token` removed.

### Fixed
- **Fallbacks** — `api/st_version.php` and `daemon/surveytrace_version.py` default to `0.16.0` when `VERSION` is missing.

### Removed
- **Pull auth** — Legacy global pull token and `POST rotate_pull_token` path removed.

## [0.15.0]

### Added
- **Scan scopes & reporting filters** — `scan_scopes`, `scan_jobs.scope_id`, `scan_scope_baselines`; `api/scan_scopes.php`; `lib_scan_scopes.php`; reporting and Reports & Analysis support named / unscoped / all filters, `scope_context`, cross-scope compare cautions (`st_reporting_unscoped_jobs_compatible`). Schema/migrations in `api/db.php`.
- **Integrations push + pull** — `integrations` table; `api/integrations.php`, `lib_integrations.php`, `lib_integrations_dashboard.php`, `lib_integrations_outbound.php`; manual push test/sample; read-only pull APIs (`integrations_metrics.php`, `integrations_events.php`, `integrations_report_summary.php`, `integrations_dashboard.php`); per-integration pull tokens (migrations in `api/db.php`); starter `integrations/starter/` (Splunk + Grafana); admin Integrations UI; `deploy.sh` ships integration PHP and copies starters to `/opt/surveytrace/integrations-starter/`.

### Changed
- **Version alignment** — `VERSION` 0.15.0 was the SemVer line where scan scopes and the integrations surface landed together. README changelog and `RELEASE_NOTES.md` stay aligned per release; 0.16.0 above is the next integrations-focused patch.
- **Documentation** — README describes completed capabilities (scan scopes, integrations, Zabbix connector); upcoming work described as named tracks; starter readmes cross-linked to Integrations (push and pull).

### Fixed
- **Fallbacks** — `api/st_version.php` and `daemon/surveytrace_version.py` use `0.15.0` when `VERSION` is missing or unreadable.

### Removed
- None.

## [0.14.3]

### Added
- **Per-integration pull tokens** — Route-specific bearer verification; `pull_client` on JSON pull responses; usage timestamps; UI per-row rotate.

### Changed
- See `RELEASE_NOTES.md`.

### Fixed
- None.

### Removed
- None.

## [0.14.2]

### Added
- None.

### Changed
- **Integrations hardening** — `integrations_metrics.php` rejects invalid `format=`; packaging/docs validation for pull APIs and legacy webhook behavior.

### Fixed
- None.

### Removed
- None.

## [0.14.1]

### Added
- **Integrations foundation** — First ship of `integrations`, global pull token, push helpers, four pull endpoints, Integrations UI, starter packages, scope fields on integration event envelopes where applicable.

### Changed
- See `RELEASE_NOTES.md`.

### Fixed
- None.

### Removed
- None.

## [0.13.0]

### Added
- **Reporting foundation** — `api/lib_reporting.php`, `api/reporting.php`, `api/reporting_cli.php`; reporting schema/migrations in `api/db.php`; `report_artifacts`; schedule action `report`; legacy global baseline job id stored in `config` (historical key name in code).
- **API surfaces** — `compare_summary`, `artifact_summary`, admin `artifact_payload_preview`; existing `compare`, `summary`, `trends`, `compliance`, `artifacts`, `set_baseline`.
- **Reports & Analysis UI** — Sidebar tab: baseline status, snapshot drift narrative, bounded compare summary, lightweight `trends_summary` charts, artifact list, artifact detail (slim summary), compliance panel (bounded rule output).

### Changed
- **SQLite / ops** — Reporting CLI retries on lock; shared busy timeout / WAL behavior documented in SQLite locking and concurrency; scheduler subprocess isolation for PHP report work.

### Fixed
- **Version** — `VERSION` `0.13.0`; `api/st_version.php` / `daemon/surveytrace_version.py` fallbacks aligned.

### Removed
- None.

## [0.12.0]

### Added
- **Asset lifecycle** — Coverage-based `active` / `stale` / `retired` on `assets` (SQLite migration in `api/db.php`); `daemon/asset_lifecycle.py` + scanner/collector evaluation; `change_alerts` types `asset_stale`, `asset_retired`, `asset_reactivated`.
- **Operator fields** — `owner`, `business_unit`, `criticality`, `environment` on `assets` (API + UI); `identity_confidence`, `identity_confidence_reason` on schema.
- **Export + API** — `export.php` extended CSV/JSON columns; `assets.php` `lifecycle_status` filter.

### Changed
- **Setup / deploy** — `setup.sh` WAL/SHM ownership guard; `deploy.sh` ships `asset_lifecycle.py`, normalizes WAL sidecars, optional PHP `st_db()` bootstrap as www-data before daemon restart; `collector/deploy.sh` includes `asset_lifecycle.py`.

### Fixed
- **Version** — `VERSION` `0.12.0`; `api/st_version.php` / `daemon/surveytrace_version.py` fallbacks aligned.

### Removed
- None.

## [0.11.0]

### Added
- **Explainable CVE triage** — SQLite migration in `api/db.php`: `findings` columns for lifecycle-adjacent triage (`confidence`, `risk_score`, `detection_method`, `provenance_source`, `evidence_json`); `daemon/finding_triage.py` + scanner/collector wiring; `GET /api/findings.php` sort/filter on triage fields; Vulnerabilities + host panel + CSV/JSON export.
- **CVE intelligence** — SQLite migration in `api/db.php`: `cve_intel` (KEV metadata, EPSS, OSV ecosystems JSON); `daemon/sync_cve_intel.py` (CISA KEV JSON, EPSS file/API, OSV per-CVE); `api/feed_sync_lib.php` / `feeds.php` target `cve_intel`; dashboard + Settings status; `findings` / export expose `intel`.

### Changed
- **Fingerprint / WebFP** — stronger VMware and Proxmox classification (titles, banners, vCenter VAMI `5480`, Wappalyzer-derived rules mapped to `hv` where the tech name implies a hypervisor); see `daemon/fingerprint.py`, `daemon/scanner_daemon.py`, `daemon/sync_webfp.py`.
- **SQLite locking** — shared `daemon/sqlite_pragmas.py` + `api/db.php` `st_sqlite_runtime_pragmas()` (`60s` busy wait, optional mmap, `temp_store=MEMORY`); README section SQLite locking and concurrency documents ops and `SURVEYTRACE_SQLITE_*` env vars.
- **Version tracking** — root `VERSION` file + `api/st_version.php` / `daemon/surveytrace_version.py`; `deploy.sh` copies `VERSION` to `/opt/surveytrace/`.

### Fixed
- **Deploy** — `deploy.sh` ships `sync_cve_intel.py`, `sqlite_pragmas.py`, and `surveytrace_version.py`; restart web PHP after `api/db.php` so migrations 10 and 11 run.

### Removed
- None.

## [0.9.0]

### Added
- **Change detection** — SQLite `change_alerts` table and `findings` lifecycle fields (migration in `api/db.php`); `daemon/change_detection.py` drives alerts and CVE state transitions from `scanner_daemon.py` and `collector_ingest_worker.py`; `GET/POST /api/change_alerts.php`; findings API adds `accept_risk` and lifecycle-aware resolve / unresolve / `GET ?lifecycle=`; Change alerts sidebar tab with dismiss controls (scan editors+).

### Changed
- **Deploy note** — copy `change_detection.py` and `change_alerts.php`; restart Apache/php-fpm once so migrations run.

### Fixed
- None.

### Removed
- None.

## [0.8.2]

### Added
- **Scan profiles** — pipeline validation allows Full TCP to run banner/fingerprint work despite an empty fixed `port_list` (all-TCP `-p-` mode on LAN in the scanner). (`fast_full_tcp` was previously shipped and later normalized to `full_tcp`.)

### Changed
- **Scanner** — continues to union prior open ports (and related banner/CPE hints) on upsert for full-port profiles so inventory does not regress on a thin result pass.
- **Collectors** — redeploy `daemon/profiles.py` and `daemon/scanner_daemon.py` on collector hosts after upgrade (`collector/deploy.sh` copies both).

### Fixed
- None.

### Removed
- **Fast Full TCP** legacy profile option (normalized to `full_tcp`).

## [0.8.1]

### Added
- None.

### Changed
- **Collector install token** — Settings is generate-only (confirm + one-time reveal with copy); `POST /api/settings.php` no longer accepts a raw `collector_install_token` field.
- **Collector overview** — list API exposes `online_recent_2m` so aggregate “online (<=2m)” counts match per-row freshness; “Set ranges” uses a modal instead of a browser prompt.
- **Fingerprinting** — Linux SSH/distro evidence prevents an open RDP port alone from classifying the host as a Windows workstation (better for Linux VMs with xrdp or similar).

### Fixed
- None.

### Removed
- Raw `collector_install_token` write path in Settings POST.

## [0.8.0]

### Added
- **Collector architecture (MVP + parity runner)** — added collector registration/auth (`collector_checkin.php`, `collector_jobs.php`, `collector_submit.php`), management API (`collectors.php`), ingest worker (`collector_ingest_worker.py`), and remote collector packaging under `collector/`.
- **Centralized enrichment + isolated collectors** — collectors run local parity discovery and upload chunked artifacts; master performs CVE/AI enrichment asynchronously.
- **Unified scheduling model** — collectors use the same `scan_schedules` engine as master scans (`collector_id`), including cron, pause/resume, and missed-run policies.
- **UX and role coverage** — scan/schedule forms support collector targeting, scan queue/history/detail show source, Settings adds install token management, collector overview adds status/assignment/token controls; scan editors can target collectors while collector mutations remain admin-only.
- **Safety guardrails** — per-collector allowed CIDR ranges are enforced at queue/save, run-now, schedule assignment, scheduler enqueue, and collector dispatch.

### Changed
- None.

### Fixed
- None.

### Removed
- None.

## [0.7.0]

### Added
- **On-demand operator AI** — `POST /api/ai_actions.php` (`findings_guidance`, `explain_host`, `refresh_scan_summary`; Ollama helpers inlined in that file). Host detail panel adds AI operator hints with cached results on `assets.ai_findings_guidance_cache` / `assets.ai_host_explain_cache` (migrated on startup). Scan history detail adds **Refresh AI summary** for `done` jobs.

### Changed
- **Minor release (operator AI)** — bumps the minor version because this release adds a new on-demand AI surface (not just a patch).
- **Scan AI summary reliability** — daemon uses a longer Ollama timeout for run-wide summaries, always records `ai_scan_summary_status` / `ai_scan_summary_detail` when AI is enabled, and scan/dashboard/history paths decode `summary_json` more robustly (including UTF-8 substitution). UI shows structured summary or status detail so completed runs are not blank.

### Fixed
- **Deploy** — `deploy.sh` copies `ai_actions.php` and post-deploy checks verify it.

### Removed
- None.

## [0.6.2]

### Added
- **Scheduled + on-demand DB backups** — scheduler-managed DB backups with Settings controls (enable, cron, retention days, keep-count), backup status telemetry, plus an admin **Run backup now** action and restore helper script.

### Changed
- **Host rescan modal parity** — Assets host rescan now exposes the same scan controls as manual/scheduled workflows: profile defaults, scan step selection, rates, discovery mode, exclusions, and per-run enrichment selection.
- **Deep Scan vs Full TCP clarity + behavior** — UI/help text and profile descriptions now explicitly distinguish Deep Scan (fixed expanded list) from Full TCP (`-p-` all ports on LAN). `full_tcp` now uses longer host-timeout tiers on small scopes to reduce empty-result runs.
- **Full TCP overwrite guard** — daemon upsert path now preserves prior inventory signal by unioning `open_ports` (and merging banners / fallback CPE data) when a weak `-p-` pass returns fewer results.

### Fixed
- None.

### Removed
- None.

## [0.6.1]

### Added
- **Audit attribution for trash lifecycle** — added audit events for `scan.job_trashed`, `scan.job_restored`, `scan.job_purged`, and `scan.trash_retention_updated`.

### Changed
- **Scan delete hardening** — trash lifecycle (move to trash, restore, admin-only permanent delete) with retention-based automatic purge.
- **Trash retention controls** — configurable retention (`scan_trash_retention_days`) is exposed in Settings and enforced by scheduler-side purge logic.
- **Scan history trash views + RBAC** — Scan History now supports Active/Trash/All semantics with role enforcement: viewers are active-only, scan editors/admins can manage trash actions, and admin is required for permanent purge and retention changes.

### Fixed
- None.

### Removed
- None.

## [0.6.0]

### Added
- **Profile + account recovery UX** — My Profile self-service, modal-based admin temporary password flows, forced first-login password change, and improved MFA setup/recovery handling.

### Changed
- **Identity/auth hardening** — OIDC-only SSO path, RBAC coverage pass, OIDC JWKS signature validation, and role-aware UI gating.

### Fixed
- None.

### Removed
- None.

## [0.5.0]

### Added
- **Device identity** — `devices` table and `assets.device_id` (FK); idempotent migration (`migration_device_identity_v1` in `config`) in `api/db.php` and `daemon/scanner_daemon.py`; 1:1 backfill for legacy rows.
- **API** — `GET/POST /api/devices.php` (list, detail, merge), `GET /api/assets.php?device_id=`, `GET /api/export.php?device_id=`, dashboard includes `device_id` in top-vulnerable query.
- **UI** — Devices tab, device detail side panel (with merge), Assets integration (filter, sort, single search + numeric device id + Enter, clear filters); `deploy.sh` copies `api/devices.php` (required for the Devices tab).
- **Docs** — `docs/DEVICE_IDENTITY.md` (device vs address model and API notes).

### Changed
- **Scanner** assigns / preserves `device_id` on asset upsert; optional fill of `devices.primary_mac_norm` when a MAC is learned.
- **Scan history search** — `GET /api/scan_history.php` accepts optional `q` (max 120 chars) to filter list rows by `scan_jobs.label`, `target_cidr`, or `id`. Scan history page search (debounced) uses `limit=200` when `q` is set; queue panel still reflects unfiltered `GET /api/scan_status.php` history. Run detail assets include `device_id` for navigation to Devices / Assets.

### Fixed
- None.

### Removed
- None.

## [0.4.0]

### Added
- **NVD API key** — optional key in Settings (stored in SQLite, not echoed on read) or `NVD_API_KEY` in the environment (env wins). Improves NVD feed sync rate limits for `sync_nvd.py`, cron, and in-app sync.
- **Per-scan enrichment** — `POST /api/scan_start.php` accepts optional `enrichment_source_ids` (omit = all enabled, `[]` = skip external enrichment for that run, `[id,…]` = subset). Stored on `scan_jobs` and honored by `scanner_daemon.py`.

### Changed
- **Schedules** — `scan_schedules` gains `enrichment_source_ids`; schedule UI and `POST /api/schedules.php` align with manual scan options (scan step list, `rate_pps` / `inter_delay`, priority, enrichment subset, profile confirmation for high-impact profiles). Scheduler enqueues jobs with the same fields.
- **Schema** — `sql/schema.sql` `scan_jobs` expanded to match migrated production columns; `dashboard.php` / `schedules.php` migrations cover any straggler columns on first request.

### Fixed
- **Scanner** — external enrichment no longer holds a SQLite write transaction during slow calls (avoids UI/API stalls during UniFi or SNMP timeouts).

### Removed
- None.

## [0.3.0]

### Added
- **Scheduling foundations** — cron-based schedule model, scheduler daemon service, schedule CRUD/run controls, and timezone-aware next-run handling in UI/API.
- **Discovery expansion** — routed-friendly host discovery modes (`auto` / `routed` / `force`), broader hostname/service discovery, and early enrichment/fingerprinting quality improvements.

### Changed
- **Queue and execution improvements** — support for multiple queued jobs, sequential execution by priority/age, queued cancel and running abort actions, and retry workflow improvements.

### Fixed
- None.

### Removed
- None.

## [0.2.0]

### Added
- **Safer defaults and scan profiles** — profile-driven scanning introduced with guarded defaults for different environments.
- **Profile-aware scanning pipeline** — per-profile step selection, rates, delays, and port behavior enforced by daemon and stored on scan jobs.
- **High-impact confirmation gates** — confirmation prompts added for higher-risk scan behaviors before execution.

### Changed
- None.

### Fixed
- None.

### Removed
- None.
