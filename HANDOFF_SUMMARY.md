# SurveyTrace Handoff Summary (2026-04-30)

Use this as a context starter in a new conversation.

**Release:** **0.8.1** (`ST_VERSION` in `api/db.php`) — patch on **0.8.0** collector MVP: install-token UX/API hardening, collector overview accuracy + CIDR modal, Linux+RDP fingerprint fix. Prior headline releases remain **0.7.0** (operator AI) and **0.6.x** (rescan parity, full-TCP safeguards, DB backup/restore, Phase 7 trash).

## Where things stand

- **Phase 8 (collectors)** — MVP is in-tree: registration/check-in, job lease/submit, ingest worker path, `collector/` packaging, UI overview + Settings, schedule `collector_id`, CIDR guardrails. Treat operational hardening (ingest scale, token rotation UX, more tests) as follow-on, not “not started.”
- **Phases 1–7** — Delivered in practical scope (profiles, queue/scheduling, discovery, device identity, access hardening, scan trash/retention). Phase 5 optional follow-ons remain deferred unless needed.
- **Roadmap detail** — See **`README.md`** for Phases 9+ (change lifecycle, CVE quality, asset lifecycle, baselines, integrations, UI modularization, credentialed checks, governance).

## Session updates (2026-04-30)

- **Collector install token** — UI is generate-only (confirm → API generate → one-time reveal modal with copy, no backdrop dismiss). **`api/settings.php`** rejects `collector_install_token` in POST; only **`collector_install_token_generate`** creates/rotates the value. **`collector/README.md`** install steps aligned.
- **Collector overview** — **`api/collectors.php`** adds **`online_recent_2m`** per row so summary “online (<=2m)” matches **`last_seen_at`**; **Set ranges** uses in-app modal (`public/index.php` + **`z218`** in **`public/css/app.css`**).
- **Fingerprinting** — **`daemon/fingerprint.py`**: when combined banners show Linux distro SSH (or xrdp), **3389** is omitted from the Windows port-profile pass so CPE/category are not stuck on Windows+RDP for Linux VDI/xrdp hosts.

## Next suggested steps

1. **Collector ops** — production checklist for remote collector + ingest worker; monitor `collector_ingest_queue` depth and failed chunks from health/UI.
2. **Regression tests** — collectors list JSON includes `online_recent_2m`; settings POST rejects `collector_install_token`; optional fingerprint fixture for Linux+3389+SSH banner.
3. **Roadmap** — pick up Phase 9+ items from **`README.md`** when collector slice is stable in your environment.

## Important files (recent touchpoints)

- `api/db.php` — `ST_VERSION`
- `api/settings.php`, `api/collectors.php`, `api/collector_checkin.php`
- `public/index.php`, `public/css/app.css`
- `daemon/fingerprint.py`, `daemon/sync_nvd.py` (User-Agent version)
- `RELEASE_NOTES.md`, `README.md` (changelog), `collector/README.md`

## Phase 5 reference (unchanged)

- **`docs/DEVICE_IDENTITY.md`**, **`api/devices.php`**, **`api/assets.php`**, **`daemon/scanner_daemon.py`**, **`deploy.sh`** (must ship `devices.php` with UI).
