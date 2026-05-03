# SurveyTrace Release Notes

Release notes for shipped app versions.  
For roadmap and deep technical context, see `README.md`.

## 0.16.0 (2026-05-01)

- **Integrations admin UI** — Push vs Pull/API sections, friendly type labels, type-aware create/edit (modal), quick-start guidance, per-row token reveal copy (“will not be shown again”). Removed **Rotate legacy global pull token**.
- **Pull authentication** — **`config.integrations_pull_token_bcrypt`** and **`POST … rotate_pull_token`** removed. Pull routes verify **only** enabled per-integration **`token_hash`** rows of the matching pull type (**401** invalid/missing token; **503** when no enabled row for that route has a usable token). Migration **`migration_phase16_remove_legacy_integrations_pull_token_v1`** deletes the legacy config key if present.
- **Admin API** — **`GET /api/integrations.php`**: removed **`legacy_pull_token_configured`** and **`pull_token_configured`**; list rows add **`type_label`**, **`mode`**, **`destination_summary`**. Create/update strip push-only fields when **`type`** is a pull integration.
- **Splunk starter app** — **`bin/surveytrace_events.py`** (JSONL pull + checkpoint), **`default/inputs.conf`**, **`default/surveytrace_pull.ini.example`**, **`default/data/ui/nav/default.xml`**, **`default/data/ui/views/surveytrace_overview.xml`**; README documents **`local/surveytrace_pull.ini`**.
- **Docs** — README Integrations section and Grafana starter README updated for per-integration tokens only; **`VERSION` 0.16.0** with **`api/st_version.php`** / **`daemon/surveytrace_version.py`** fallbacks aligned.

## 0.15.0 (2026-05-03)

- **Version / changelog alignment** — **`VERSION` 0.15.0** aligns semver with completed roadmap **Phase 15** (integrations) and **Phase 14** (scan scopes). README **Changelog** now lists **0.14.1–0.14.3** and **0.15.0**; patch detail for **0.14.x** remains in the sections below.
- **Scan scopes & reporting (Phase 14)** — **`scan_scopes`**, **`scan_jobs.scope_id`**, **`scan_scope_baselines`**; scoped baselines and reporting filters; **`migration_phase14_scan_scopes_v1`**.
- **Integrations (Phase 15)** — Push/pull integration surface shipped across **0.14.1–0.14.3** (table, endpoints, per-row tokens, starters, UI); migrations **`migration_phase14_1_integrations_v1`** and **`migration_phase14_1_integrations_per_pull_token_v1`**.
- **Documentation** — README roadmap and section naming; starter **`integrations/starter/**`** readmes.
- **Version fallbacks** — **`api/st_version.php`** and **`daemon/surveytrace_version.py`** default to **`0.15.0`** when **`VERSION`** cannot be read.

## 0.14.3 (2026-05-01)

- **Integrations — per-integration pull tokens** — Migration **`migration_phase14_1_integrations_per_pull_token_v1`**: **`integrations.token_hash`**, **`token_created_at`**, **`token_last_used_at`**, **`token_last_used_ip`**. **`POST /api/integrations.php`** **`rotate_token`** + **`integration_id`** returns **`token`** once per row. **`prometheus_pull`** / **`json_events_pull`** / **`report_summary_pull`** map to metrics / events / (report summary + dashboard) pull routes only. *(Superseded in **0.16.0**: legacy global **`config.integrations_pull_token_bcrypt`** and **`rotate_pull_token`** removed.)*
- **Pull responses** — JSON pull endpoints may include **`pull_client`** (`integration_id`, `integration_name`, `integration_type`).
- **UI** — Per-row pull token status, **Generate / Rotate token** on pull types.
- **Documentation** — **`README.md`** and **`integrations/starter/**`** readmes: roadmap-only phase numbering, descriptive body headings, current-ship summary; **`RELEASE_NOTES.md`** bullets use feature titles (migration keys unchanged). **`sql/schema.sql`** aligned with per-row pull token columns.

## 0.14.2 (2026-05-01)

- **Packaging / validation** — **`VERSION`** matches this release. **`deploy.sh`** includes all integration API PHP files and copies **`integrations/starter/`** to **`/opt/surveytrace/integrations-starter/`**.
- **Pull API** — **`integrations_metrics.php`** rejects unknown **`format=`** with HTTP **400** (only **`prometheus`** or **`json`**).
- **Docs / legacy webhook** — Clarified that **`integration_webhook_*`** settings are stored but **`st_integrations_outbound_emit()`** is not invoked by reporting or the scheduler (push validation is **`integrations.php`** test/sample).

## 0.14.1 (2026-05-01)

- **Integrations foundation** — Migration **`migration_phase14_1_integrations_v1`**: **`integrations`** table (push target config + operator markers for pull types). Config key **`integrations_pull_token_bcrypt`** holds a **`password_hash`** for Bearer / `?token=` access to read-only pull endpoints.
- **Admin API** — **`GET/POST /api/integrations.php`** (admin, CSRF on POST): list/create/update/delete integrations; **`test`** / **`sample`** manual outbound sends (canonical **`surveytrace.reporting.event.v1`** JSON); **`rotate_pull_token`** returns the new token once. Responses never include **`auth_secret`**.
- **Push helpers** — **`api/lib_integrations.php`** implements **`webhook`** (optional HMAC), **`splunk_hec`**, **`loki`** push, **`syslog`** (UDP default, optional TCP via **`extra_json.syslog_transport`**). Shared short-timeout HTTPS POST in **`api/lib_integrations_outbound.php`** (`st_integrations_http_post_json`).
- **Pull endpoints** — **`GET /api/integrations_metrics.php`** (Prometheus text or **`?format=json`**), **`GET /api/integrations_events.php`**, **`GET /api/integrations_report_summary.php`**, **`GET /api/integrations_dashboard.php`**. All require a configured pull token (global at first ship).
- **Reporting** — Removed automatic **`st_reporting_emit_artifact_integration_event`** calls after scheduled report materialization (**foundation-only**; no broad automatic export fan-out). Reserved **`integration_webhook_*`** settings are not invoked by the server.
- **UI** — Sidebar **Integrations** tab (admin): list, create, prompt-based edit, test/sample, enable/disable, delete, rotate pull token; shows last test status and redacted targets.
- **Docs** — **`README.md`** integrations section expanded (Grafana / Splunk patterns, security, sample payloads). **`deploy.sh`** ships new PHP files.
- **Starter packages** — **`integrations/starter/splunk_surveytrace/`** (Splunk app + **`surveytrace:reporting:event`**) and **`integrations/starter/grafana/`** (Infinity starter dashboard + README); copied on deploy to **`/opt/surveytrace/integrations-starter/`**. **`integrations_report_summary`** / **`integrations_events`** envelopes include flat **`scope_id`** / **`scope_name`** where applicable (`flat_scope` for events).

## 0.13.0 (2026-05-01)

- **Reporting & baselines (foundation)** — Migration **`migration_phase13_reporting_v1`**: **`scan_jobs.is_baseline`**, **`scan_schedules.schedule_action`** (`scan` \| `report`), **`report_artifacts`** (JSON payloads for scheduled reports), config key **`phase13_baseline_job_id`**. Library and HTTP surface: **`api/lib_reporting.php`**, **`api/reporting.php`**, **`api/reporting_cli.php`** (CLI invoked by the scheduler for **`report`** schedules). Snapshot diffs are **job-scoped only** (not live **`assets`/`findings`**). Baseline **config** may point at a deleted or invalid job; **`st_reporting_resolve_baseline_job_id`** treats that as no effective baseline for comparisons. **`st_reporting_trends`** uses batched aggregates (avoids N+1). **`st_reporting_set_baseline`** uses **`BEGIN IMMEDIATE` … `COMMIT`**.
- **`trends_summary`** — **`GET …?action=trends_summary&limit=`** (default **30**, max **50**): recent **`done`** jobs with **`finished_at`**, **`asset_count`**, **`open_findings_total`**, **`open_findings_by_severity`** — same batched aggregates as **`trends`**, canonical field names for UI.
- **`compare_summary`** — Same job-pair inputs as **`compare`**; JSON response carries **`diff_summary`** (counts, **`finding_events`**, warnings) without full diff row arrays (intended for UI and light clients).
- **`artifact_summary`** — **`GET …?action=artifact_summary&id=`** returns metadata plus decoded **`summary`**, **`delta`**, **`compliance_summary`**, **`diff_summary`** from stored report payloads; avoids shipping full **`payload_json`** to the default artifact-detail path.
- **`artifact_payload_preview`** — **Admin-only**; **`GET …?action=artifact_payload_preview&id=`** returns a **truncated** pretty-printed view of stored JSON for debugging.
- **Reporting UI** — Sidebar **Reporting** tab: baseline status (loads independently of job pickers), **trends** (**`trends_summary`**, max **50** jobs, snapshot-count tables + small inline SVG sparklines), two-job **compare summary**, saved **artifacts** list, **artifact** detail modal (**`artifact_summary`** — slim over the wire), and **compliance summary** (live **`compliance`**, bounded rule text). Default paths avoid **`compare`** full diff rows and **`artifact`** full payloads.
- **SQLite locking / performance hardening** — Shared **`daemon/sqlite_pragmas.py`** + **`api/db.php`** busy timeout / WAL (see **`README.md`** → *SQLite locking and concurrency*). Reporting CLI **materialize** retries on **`database is locked` / busy** with backoff; scheduler runs report materialization in a **subprocess** so the daemon does not hold SQLite during long PHP report work.
- **Follow-up** — CSV export, charts, and optional “report immediately after scan completes” automation remain future work.

## 0.12.0 (2026-05-01)

- **Asset lifecycle** — Coverage-based **stale** / **retired** status (not “age since last_seen”): after each completed scan job, assets whose **IP is inside the job’s `target_cidr`** but missing from that job’s **`scan_asset_snapshots`** increment **`missed_scan_count`**; first miss → **`stale`**, second+ → **`retired`** (with **`retired_at`**). Observing a host again (**scanner** `upsert_asset` or **collector** ingest) resets to **active** and clears misses. **`change_alerts`**: **`asset_stale`**, **`asset_retired`**, **`asset_reactivated`**. Migration: **`migration_phase12_asset_lifecycle_v1`** (`api/db.php`). Daemons: **`daemon/asset_lifecycle.py`**, **`scanner_daemon.py`**, **`collector_ingest_worker.py`**, **`change_detection.py`**.
- **Business / identity context on `assets`** — **`owner`**, **`business_unit`**, **`criticality`**, **`environment`** (API PUT + UI edit modal); **`identity_confidence`**, **`identity_confidence_reason`** (schema for future enrichment). **`GET /api/assets.php`** filter **`lifecycle_status`**; **Assets** table lifecycle badge + filter.
- **Export** — **`api/export.php`** CSV/JSON include lifecycle columns (after **Last Seen**, before **Notes**); optional **`lifecycle_status`** query filter; finding sub-rows stay column-aligned.
- **Setup / deploy** — **`setup.sh`**: WAL/SHM sidecar ownership if present; comments on fresh schema vs PHP migrations. **`deploy.sh`** / **`collector/deploy.sh`**: ship **`asset_lifecycle.py`**; normalize **`surveytrace.db-wal`** / **`-shm`** permissions; optional **`php -r 'require api/db.php; st_db();'`** from install root as **www-data** to apply migrations before daemon restart; post-deploy check for **`asset_lifecycle.py`**.
- **SQLite concurrency (recap)** — Shared **`daemon/sqlite_pragmas.py`** + **`api/db.php`** busy timeout / WAL (see README). Deploy reminds that the **data directory** must allow WAL file creation for **surveytrace** + **www-data**.

## 0.11.0 (2026-05-01)

- **Explainable CVE triage** — Migration `migration_phase10_finding_triage_v1`: new **`findings`** fields (**`confidence`**, **`risk_score`**, **`detection_method`**, **`provenance_source`**, **`evidence_json`**, related lifecycle timestamps as applicable). **`daemon/finding_triage.py`** and scanner/collector paths populate triage; **`GET /api/findings.php`** supports confidence/sort filters; **Vulnerabilities** tab and host detail show triage; **`findings_export.php`** adds columns.
- **CVE intelligence** — migration `migration_phase11_cve_intel_v1`: **`cve_intel`** table (KEV flags + metadata, EPSS scores/percentile, OSV ecosystem JSON, sync timestamps). **`daemon/sync_cve_intel.py`** ingests CISA KEV, FIRST EPSS (bulk file and/or per-CVE API fallback), and OSV **`/v1/vulns/{CVE}`**; **`api/feed_sync_lib.php`** / **`feeds.php`** accept sync target **`cve_intel`** and include it in **`all`** after NVD/OUI/WebFP. Dashboard and Settings show last sync and row count; findings API joins **`intel`** for UI/export.
- **Hypervisor fingerprinting** — Improved **Proxmox VE** and **VMware ESXi / vSphere / vCenter** detection (hostnames, HTTP titles incl. port **5480**, banners, port **5480** profile, Wappalyzer rule category overrides in **`sync_webfp.py`** for hypervisor-named technologies).
- **SQLite concurrency** — Shared runtime PRAGMAs (**`daemon/sqlite_pragmas.py`**, **`api/db.php`** `st_sqlite_runtime_pragmas`): default **60s** `busy_timeout`, optional **`mmap_size`** (disable with **`SURVEYTRACE_SQLITE_MMAP_BYTES=0`** on NFS); scanner/scheduler connections use **60s** `sqlite3` timeout. See **`README.md` → SQLite locking and concurrency**.
- **Release version** — Single semver line in install-root **`VERSION`**; **`api/st_version.php`** defines **`ST_VERSION`** for PHP; **`daemon/surveytrace_version.py`** reads the same file for sync script and scanner **User-Agent** strings. **`deploy.sh`** / **`collector/deploy.sh`** copy **`VERSION`** alongside **`api/`** / **`daemon/`**.
- **Deploy** — Ensure **`daemon/sync_cve_intel.py`**, **`daemon/sqlite_pragmas.py`**, and **`daemon/surveytrace_version.py`** are on the server (**`deploy.sh`** copies them); run **`sync_webfp.py`** once after upgrade so regenerated **`data/webfp_rules.json`** picks up **`hv`** category overrides. Restart **Apache/php-fpm** (or touch **`api/db.php`** load path) so SQLite migrations **10** and **11** apply.

## 0.9.0 (2026-05-01)

- **Change detection** — New **`change_alerts`** table and **`findings`** lifecycle columns (`lifecycle_state`, `mitigated_at`, `accepted_at`, `accepted_by_user_id`, job id stamps). The scanner and collector ingest worker record **new asset**, **port change**, **new CVE**, **finding mitigated** (CVE absent from correlated results for assets in the run), and **finding reopened** (CVE returns after `mitigated`).
- **API** — **`GET/POST /api/change_alerts.php`** (list/dismiss open alerts). **`findings.php`** exposes lifecycle fields on **GET**, adds **`accept_risk`**, and maps **resolve** / **unresolve** to lifecycle-aware updates.
- **UI** — **Change alerts** sidebar page with refresh and per-row / dismiss-all (scan editor or admin).
- **Deploy** — Ship **`daemon/change_detection.py`**, **`api/change_alerts.php`**, updated **`scanner_daemon.py`** / **`collector_ingest_worker.py`** / **`findings.php`** / **`db.php`**; collectors need **`change_detection.py`** beside **`scanner_daemon.py`**. Restart **web PHP** once after **`db.php`** so SQLite migrations apply.

## 0.8.2 (2026-05-01)

- **Scan profiles** — `validate_phases()` now treats **Full TCP** and **Fast Full TCP** like other banner-capable profiles even though their fixed port list is empty (all-TCP mode uses `-p-` in the daemon). Phases line up with profile intent instead of silently dropping banner work.
- **Fast Full TCP** — service detection uses **version intensity 3** (same floor as Standard Inventory) so completed runs are not systematically weaker on CPEs than a normal inventory pass. **Routed / VPN** jobs use a **broad finite port union** (safe ports + standard inventory list + configured extras) instead of a full `-p-` sweep, so long or filtered paths still return useful inventory without timing out empty.
- **Scanner daemon** — LAN **Fast Full TCP** tuning: larger host batches where appropriate, **`-T4`**, and profile-specific **host-timeout** tiers; **routed** mode keeps conservative batching. **Full / Fast Full TCP** upsert logic still **merges prior open-port evidence** so a weak pass does not wipe better inventory.
- **Collectors** — behavior is defined by the shipped **`profiles.py`** and **`scanner_daemon.py`** on each node; run **`collector/deploy.sh`** (or equivalent) after pulling this release so remote collectors match master scan semantics.

## 0.8.1 (2026-04-30)

- **Collector install token (Settings)** — generate-only admin flow: confirm modal, server-side `collector_install_token_generate`, one-time reveal modal with copy; removed manual paste/save. `POST /api/settings.php` rejects direct `collector_install_token` body field (use UI generate or ops-level config if ever required).
- **Collector overview** — `GET /api/collectors.php` includes per-row `online_recent_2m` so the “online (<=2m)” summary matches each collector’s last seen; allowed CIDR “Set ranges” uses an in-app modal instead of `window.prompt`.
- **Fingerprinting** — when banners show strong Linux evidence (e.g. distro OpenSSH), RDP (3389) alone no longer forces a Windows workstation port profile (improves xrdp / VDI / Kasm-style hosts).

## 0.8.0 (2026-04-30)

- **Collector architecture (MVP + parity runner)** — added collector registration/auth (`collector_checkin.php`, `collector_jobs.php`, `collector_submit.php`), management API (`collectors.php`), ingest worker (`collector_ingest_worker.py`), and remote collector packaging under `collector/`.
- **Centralized enrichment + isolated collectors** — collectors run local parity discovery and upload chunked artifacts; master performs CVE/AI enrichment asynchronously.
- **Unified scheduling model** — collectors use the same `scan_schedules` engine as master scans (`collector_id`), including cron, pause/resume, and missed-run policies.
- **UX and role coverage** — scan/schedule forms support collector targeting, scan queue/history/detail show source, Settings adds install token management, collector overview adds status/assignment/token controls; scan editors can target collectors while collector mutations remain admin-only.
- **Safety guardrails** — per-collector allowed CIDR ranges are enforced at queue/save, run-now, schedule assignment, scheduler enqueue, and collector dispatch.

## 0.7.0 (2026-04-29)

- **Minor release** — new operator-facing AI capabilities and related persistence warrant `0.7.0` rather than a patch-only bump.
- **Scan completion AI summary** — longer Ollama timeout for run-wide summaries; scan `summary_json` always carries `ai_scan_summary_status` / `ai_scan_summary_detail` when AI is enabled; safer JSON decode for history and dashboard; host/executive UI shows structured `ai_summary` or the recorded status when the model or runtime fails.
- **On-demand operator AI** — new `POST /api/ai_actions.php` (self-contained): **CVE triage** and **explain this host** (cached per asset on new columns, fingerprinted by findings/host context), plus **refresh scan summary** for completed jobs without re-running the scan.
- **Host panel** — “AI operator hints” section with generate/regenerate controls (scan editor / admin); viewers may read cached text.
- **Deploy** — `deploy.sh` includes `api/ai_actions.php` and verifies it under `/opt/surveytrace/api/`.

## 0.6.2 (2026-04-29)

- Host rescan modal now mirrors manual/scheduled scan controls:
  profile defaults, phases, rates, discovery mode, exclusions, and per-run enrichment.
- Clarified Deep Scan vs Full/Fast Full TCP behavior in UI/help text and profile descriptions.
- Improved `full_tcp` behavior for small scopes with longer host-timeout tiers.
- Protected existing inventory from weak full-port passes by merging prior open-port evidence on upsert.
- Added scheduler-managed database backups (`backup_db.sh`) with Settings controls:
  enable, cron, retention days, keep-count.
- Added admin **Run backup now** action in Settings.
- Added `restore_db.sh` helper for controlled restore workflow.
- Added enrichment file-path jail controls for file-based sources (DHCP/DNS/firewall logs).
- Fixed CVE host filter race where “View CVEs” could show unfiltered results.

## 0.6.1

- **Scan delete hardening** — trash lifecycle, restore flow, admin-only permanent purge, retention-based cleanup.
- Scan history Active/Trash/All views with role enforcement.
- Audit attribution for trash lifecycle actions.
