# SurveyTrace Release Notes

Release notes for shipped app versions.  
For roadmap and deep technical context, see `README.md`.

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

- Phase 7 scan delete hardening:
  trash lifecycle, restore flow, admin-only permanent purge, retention-based cleanup.
- Scan history Active/Trash/All views with role enforcement.
- Audit attribution for trash lifecycle actions.

