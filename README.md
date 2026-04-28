# SurveyTrace

A self-hosted network asset discovery and inventory platform for general-purpose networks.

## Features

- **Active scanning** — ARP sweep, ICMP ping, TCP SYN discovery, nmap banner/service detection
- **Passive discovery** — ARP sniff, mDNS/Bonjour service type detection
- **HTTP title grabbing** — identifies self-hosted services by page title (Portainer, Grafana, Jellyfin, ~80 others)
- **CVE correlation** — matches detected CPEs against a local NVD database (no cloud API required); optional NIST API key via **Settings** or `NVD_API_KEY` for faster NVD sync rate limits
- **Feed sync** — scheduled IEEE OUI + Wappalyzer signature imports for fresher fingerprinting
- **Manual feed sync UX** — in-app sync progress/status indicators, output viewer, and single-sync guard
- **Scan profiles** — IoT Safe, Standard Inventory, Deep Scan, Full TCP, Fast Full TCP, OT Careful
- **Job queue** — multiple queued scans with priority, auto-retry, and per-job progress
- **Scheduling** — cron-based scheduled scans with timezone support; schedule editor mirrors manual scan options (phases, rate limits, priority, discovery mode, per-run enrichment subset, high-impact profile confirmation)
- **Scan history** — dedicated **Scan history** sidebar page: job queue, finished runs, and a debounced filter by **scan label**, target CIDR, or job id (`GET /api/scan_history.php` with **`q`**, up to **`limit=200`**; see `api/scan_history.php`). From a run’s **Details** modal, click a catalogued host row to jump to **Devices** (when `device_id` is set) or **Assets** host detail by IP. **Scan control** remains the page to queue new jobs.
- **UI themes** — Dark / Light / Auto mode with persistent preference
- **Executive dashboard view** — presentation-focused dashboard mode
- **System health** — **System** sidebar tab: live operational summary (background services, disk, databases, scan queue, feed sync) via `GET /api/health.php` (read-only, no config changes)
- **Enrichment** — optional Phase 3b metadata from controllers, SNMP, DHCP/DNS/firewall log imports, and other pluggable sources; per-scan source selection on the Scan tab (omit = all enabled sources)
- **Asset fingerprinting** — OUI lookup, hostname patterns, port profiles, banner analysis, Proxmox node-name extraction
- **Vulnerability tracking** — CVSS scoring, severity filtering, CSV/JSON export
- **Multi-subnet** — auto, routed, and force (-Pn) discovery modes
- **Device identity (Phase 5)** — logical **`devices`** rows with **`assets.device_id`** (stable id per inventory host; merge duplicates via API/UI). See **`docs/DEVICE_IDENTITY.md`**.

## Requirements

- Ubuntu 22.04+ or Debian 12+
- Python 3.10+
- PHP 8.1+ with SQLite3 extension
- Apache 2.4+ (or another PHP-capable web stack; **PHP-FPM** is recommended so long-running feed sync can return immediately to the browser)
- nmap
- `qrencode` (for local-only MFA QR rendering)
- 2GB RAM, 10GB disk (NVD database is ~1GB)

## Quick Start

```bash
git clone https://github.com/veddegre/surveytrace.git
cd surveytrace
sudo bash setup.sh
```

The web UI will be available at `http://your-server-ip/`

## Manual Installation

```bash
# System dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-venv php php-sqlite3 \
    apache2 libapache2-mod-php nmap sqlite3

# Service user
sudo useradd -r -s /bin/false -d /opt/surveytrace surveytrace

# Deploy files
sudo mkdir -p /opt/surveytrace/{daemon,api,public,sql,docs,data}
sudo cp -r daemon/ api/ public/ sql/ docs/ /opt/surveytrace/
sudo chown -R surveytrace:surveytrace /opt/surveytrace

# Python environment
sudo -u surveytrace python3 -m venv /opt/surveytrace/venv
sudo -u surveytrace /opt/surveytrace/venv/bin/pip install scapy python-nmap requests

# Raw socket capability for passive discovery
sudo setcap cap_net_raw+eip $(readlink -f /opt/surveytrace/venv/bin/python3)

# Initialize database
sudo -u surveytrace sqlite3 /opt/surveytrace/data/surveytrace.db \
    < /opt/surveytrace/sql/schema.sql

# Systemd services
sudo cp surveytrace-daemon.service surveytrace-scheduler.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now surveytrace-daemon surveytrace-scheduler
```

## Updating / Deploying Changes

```bash
# After pulling changes from git
cd ~/surveytrace-repo
git pull
bash deploy.sh
```

`deploy.sh` copies the tracked application files from the repo into `/opt/surveytrace` (not a blind `cp -r` of the whole tree). It includes, among others:

- **`api/`** — all HTTP endpoints used by the UI, including `feeds.php`, **`feed_sync_lib.php`** (shared by `feeds.php` and `daemon/feed_sync_worker.php`), `scan_history.php`, **`devices.php`** (device list/detail + merge), `settings.php`, etc.
- **`daemon/`** — scanner, scheduler, fingerprint engine, enrichment `sources/`, **`feed_sync_worker.php`** + **`feed_sync_cancel.py`** (UI cancel / cooperative stop), and the `sync_*.py` feed scripts
- **`public/`** — `index.php` and `css/app.css`
- **`sql/schema.sql`** — reference copy for new installs (existing DBs are migrated by the app on startup)

It then restarts `surveytrace-daemon` and `surveytrace-scheduler`.

**Feed sync from the browser:** Under **PHP-FPM**, sync runs in the same request after `fastcgi_finish_request()`. Under **Apache `mod_php`**, the API spawns `php daemon/feed_sync_worker.php …` in the background, which requires `exec()` not to be in `disable_functions`, and requires `feed_sync_worker.php` to be present on disk (deploy copies it). NVD runs with **`--recent`** from PHP so the job matches weekly cron behavior and stays within typical HTTP worker limits.

SQLite schema changes apply automatically on next API or daemon startup (`ALTER TABLE` migrations); fresh installs use `sql/schema.sql` with a complete `scan_jobs` definition.

## Changelog

### Unreleased

- **Scan history workflow** — dedicated **Scan history** page plus queue visibility on both **Scan control** and **Scan history**; history rows support **Details**, **Re-run**, and **Delete** actions.
- **Historical run evidence** — per-scan snapshots stored in **`scan_asset_snapshots`** and **`scan_finding_snapshots`**; scan detail prefers snapshots, falls back to legacy `last_scan_id`, then `port_history` for older runs.
- **Run comparisons** — scan detail now computes diffs (hosts, ports, CVEs) versus previous run or a selected prior run (`compare_to`), with optional scope filters (`any`, `target`, `profile`, `both`).
- **Host/device drift views** — host detail includes per-scan change history (new/closed ports, new/resolved CVEs); device detail aggregates scan history across linked assets and can jump directly to run details.
- **Re-run label normalization** — repeated re-runs no longer stack suffixes like `(re-run) (re-run)`; labels normalize to a single suffix.
- **Identity hardening + UX refresh** — OIDC-only SSO path (SAML bridge removed), endpoint RBAC hardening, OIDC JWKS `id_token` signature validation, and role-aware UI control hiding/disabling.
- **Profile + account recovery UX** — new **My profile** surface for self-service account management (display name, email, self password change, self MFA setup/disable for local accounts); admin user-management now supports temporary password resets (forced change on first login) and user MFA reset/clear actions.
- **MFA usability improvements** — QR code enrollment, copyable setup URI, recovery code panel with copy/download/print actions, and modal-based MFA disable flow.
- **Planned next hardening** — replace hard delete with **soft delete** for scan runs, add a **Trash** view in Scan History, and auto-purge trashed runs after a configurable retention window (e.g. `scan_trash_retention_days`).

### 0.6.0

- **Identity/auth hardening** — OIDC-only SSO path, RBAC coverage pass, OIDC JWKS signature validation, and role-aware UI gating.
- **Profile + account recovery UX** — My Profile self-service, modal-based admin temporary password flows, forced first-login password change, and improved MFA setup/recovery handling.

### 0.5.0

- **Device identity (Phase 5)** — **`devices`** table and **`assets.device_id`** (FK); idempotent migration (`migration_device_identity_v1` in `config`) in **`api/db.php`** and **`daemon/scanner_daemon.py`**; 1:1 backfill for legacy rows.
- **Scanner** assigns / preserves `device_id` on asset upsert; optional fill of **`devices.primary_mac_norm`** when a MAC is learned.
- **API:** `GET/POST /api/devices.php` (list, detail, **merge**), `GET /api/assets.php?device_id=`, `GET /api/export.php?device_id=`, dashboard includes `device_id` in top-vulnerable query.
- **UI:** Devices tab, device detail side panel (with merge), Assets integration (filter, sort, single search + numeric device id + Enter, clear filters); **`deploy.sh`** copies **`api/devices.php`** (required for the Devices tab).
- **Docs:** **`docs/DEVICE_IDENTITY.md`** — device vs address model and API notes.
- **Scan history search** — `GET /api/scan_history.php` accepts optional **`q`** (max 120 chars) to filter list rows by **`scan_jobs.label`**, **`target_cidr`**, or **`id`**. **Scan history** page search (debounced) uses **`limit=200`** when **`q`** is set; queue panel still reflects unfiltered **`GET /api/scan_status.php`** history. Run detail assets include **`device_id`** for navigation to **Devices** / **Assets**.

### 0.4.0

- **NVD API key** — optional key in **Settings** (stored in SQLite, not echoed on read) or `NVD_API_KEY` in the environment (env wins). Improves NVD feed sync rate limits for `sync_nvd.py`, cron, and in-app sync.
- **Per-scan enrichment** — `POST /api/scan_start.php` accepts optional `enrichment_source_ids` (omit = all enabled, `[]` = skip Phase 3b, `[id,…]` = subset). Stored on `scan_jobs` and honored by `scanner_daemon.py`.
- **Scanner** — Phase 3b no longer holds a SQLite write transaction during slow external enrichment calls (avoids UI/API stalls during UniFi or SNMP timeouts).
- **Schedules** — `scan_schedules` gains `enrichment_source_ids`; schedule UI and `POST /api/schedules.php` align with manual scan options (phases, `rate_pps` / `inter_delay`, priority, enrichment subset, profile confirmation for high-impact profiles). Scheduler enqueues jobs with the same fields.
- **Schema** — `sql/schema.sql` `scan_jobs` expanded to match migrated production columns; `dashboard.php` / `schedules.php` migrations cover any straggler columns on first request.

## NVD Database Setup

### NVD API key (recommended)

NIST offers a free API key for the public CVE API; it raises rate limits so `sync_nvd.py` completes much faster than the anonymous tier.

1. Request a key: [NVD API key request](https://nvd.nist.gov/developers/request-an-api-key) (NIST account required).
2. **In the web UI:** open **Settings**, find the NVD section, paste the key, and click **Save**. After save, the UI only shows a masked placeholder until you **Remove** the key; you must remove it before pasting a different one (the API rejects overwrite while a key exists). The key is stored server-side in SQLite (`config.nvd_api_key` in `data/surveytrace.db`). It is **never returned** on `GET /api/settings.php` — the API only exposes `nvd_api_key_configured` (true/false).
3. **Via environment:** set `NVD_API_KEY` in the environment of the process that runs `sync_nvd.py` (systemd unit, cron, or shell). If `NVD_API_KEY` is set, it **overrides** the key saved in the database (useful when you do not want the key in SQLite, or when cron runs without reading the same DB path).

`daemon/sync_nvd.py` resolves the key in this order: **`NVD_API_KEY` env → Settings (database)**. Cron jobs run as `surveytrace` typically see only the DB key unless you export `NVD_API_KEY` in the crontab or wrapper script.

### Initial sync and cron

```bash
# Initial download (~1GB, 5-10 minutes)
sudo -u surveytrace /opt/surveytrace/venv/bin/python3 \
    /opt/surveytrace/daemon/sync_nvd.py

# Weekly update (add to crontab)
0 3 * * 0 surveytrace /opt/surveytrace/venv/bin/python3 \
    /opt/surveytrace/daemon/sync_nvd.py --recent
```

`--recent` uses a rolling window (default **14 days** of NVD “last modified”; override with `--days N`). The in-app “Sync NVD” button runs the same incremental mode (`--recent`) via PHP.

### Optional NVD tuning

- **`NVD_RESULTS_PER_PAGE`** — page size for NVD JSON 2.0 requests (default in script is **500**). Lower values can help if you see intermittent HTTP 404 on large pages; the sync script can also halve page size automatically on some errors.

## Fingerprint Feed Setup

```bash
# Pull latest MAC vendor mappings (IEEE)
sudo -u surveytrace /opt/surveytrace/venv/bin/python3 \
    /opt/surveytrace/daemon/sync_oui.py

# Pull latest web-app signature rules (Wappalyzer)
sudo -u surveytrace /opt/surveytrace/venv/bin/python3 \
    /opt/surveytrace/daemon/sync_webfp.py

# Optional cron examples
15 4 * * * surveytrace /opt/surveytrace/venv/bin/python3 /opt/surveytrace/daemon/sync_oui.py
30 4 * * * surveytrace /opt/surveytrace/venv/bin/python3 /opt/surveytrace/daemon/sync_webfp.py
```

Feed source links used by these scripts:
- IEEE OUI CSV (MA-L): https://standards-oui.ieee.org/oui/oui.csv
- IEEE MA-M CSV: https://standards-oui.ieee.org/oui28/mam.csv
- IEEE MA-S CSV: https://standards-oui.ieee.org/oui36/oui36.csv
- IEEE IAB CSV: https://standards-oui.ieee.org/iab/iab.csv
- Wappalyzer technologies JSON (raw): https://raw.githubusercontent.com/developit/wappalyzer/master/src/technologies/

Manual sync is also available from the Settings tab (buttons call `POST /api/feeds.php?sync=1`).

Manual sync behavior:
- Runs one sync action at a time from the UI (prevents overlapping clicks)
- Shows in-progress/completed/failed status inline in Settings
- Captures script stdout/stderr in the “Last feed sync log” modal (one `feed_sync_result.json` per completed run)
- **NVD** from the UI runs `sync_nvd.py --recent` (same incremental idea as the weekly cron); full rebuild is still `sync_nvd.py` without `--recent` on the CLI
- **Cancel** (NVD or “Sync all” only) touches `data/feed_sync_cancel`; Python exits after the current fetch step — expect **several minutes** for a typical incremental run (longer without an API key or when NIST has a large update batch)

### Feed sync install paths (optional)

If PHP cannot find `daemon/sync_*.py` (unusual directory layout), set **`SURVEYTRACE_ROOT`** to the SurveyTrace install root (the directory that contains `daemon/` and `api/`). When the web stack is not PHP-FPM and the worker is spawned with a CLI `php` binary, **`SURVEYTRACE_PHP_CLI`** can point to an explicit PHP binary (see `api/feed_sync_lib.php`).

## Authentication (web UI)

Password hashing and mode live in the `config` table (`auth_hash`, `auth_mode`). With no password configured, the UI is open (typical first-run).

- **`session`** (default): local login via `POST /api/auth.php?login=1`; the UI uses a session cookie after login.
- **`oidc`**: SSO login via `api/auth_oidc.php` (with JWT signature validation against provider JWKS), with optional breakglass local login.

Set `auth_mode` in **Settings → Access control** (or directly in `config`). Supported UI modes are `session` and `oidc`; legacy `basic` remains backend-compatible, and `auth_mode=saml` from older installs is treated as `oidc`. Session idle timeout is configurable under **Settings** (`session_timeout_minutes`).

### Local account lifecycle (session mode)

- **Admin-managed temporary passwords** — when admins create a local user or set a new password for a user, it is treated as a temporary password.
- **Forced first-login password change** — users with temporary passwords must set a new password before continuing.
- **My profile self-service** — users manage display name/email and (for local accounts) password + MFA in **My profile**.
- **MFA** — local accounts support TOTP + one-time recovery codes; OIDC-authenticated accounts treat password/MFA as IdP-managed.
- **MFA QR generation** — QR images are generated locally via `api/auth_qr.php` + `qrencode`; MFA secrets are not sent to external QR services.

**Phase 6 (planned):** extend **OIDC** + **local accounts** with optional **MFA** — **TOTP** (RFC 6238 authenticator apps) and **one-time recovery codes** for lockout recovery when authenticators are lost; **possible** (not yet committed) **WebAuthn** / **FIDO2** support, including **passkeys** or security keys, depending on dependency choices (e.g. a maintained server library) and scope; and in-app **RBAC** (roles from IdP claims/groups for SSO users, and app-assigned roles for local users). Intended to extend today’s **`basic`** / **`session`** / **`oidc`** model rather than replace it abruptly — see Roadmap below.

## Architecture

```
Browser → Apache → PHP API → SQLite
                                 ↕
             scanner_daemon.py     ← processes queued jobs
             scheduler_daemon.py   ← enqueues jobs on schedule
             nvd.db                ← local CVE database
```

### Directory Structure

```
surveytrace/
├── api/                    PHP API endpoints
│   ├── db.php              Database connection + auth helpers
│   ├── assets.php          Asset inventory
│   ├── findings.php        CVE findings
│   ├── findings_export.php CVE export (CSV/JSON)
│   ├── scan_start.php      Job queue
│   ├── scan_status.php     Job status, progress, audit log tail
│   ├── scan_abort.php      Job abort/cancel
│   ├── schedules.php       Schedule management
│   ├── scan_history.php    Scan run history + per-run detail; list supports optional `q` (label / target / id)
│   ├── enrichment.php      Enrichment source management
│   ├── dashboard.php       Dashboard stats
│   ├── feeds.php           Manual feed sync trigger (Settings UI)
│   ├── feed_sync_lib.php   Feed sync resolution + exec (used by feeds.php + worker)
│   ├── settings.php        Session timeout, safe ports, NVD API key (server-side)
│   ├── auth.php            Session login/status endpoint
│   ├── logout.php          Session logout endpoint
│   ├── export.php          Asset export
│   └── devices.php         Logical device list/detail + merge
├── daemon/                 Python background services
│   ├── scanner_daemon.py   Main scan worker
│   ├── scheduler_daemon.py Cron scheduler
│   ├── fingerprint.py      Asset classification engine
│   ├── profiles.py         Scan profile definitions
│   ├── sync_nvd.py         NVD database sync
│   ├── sync_oui.py         IEEE OUI feed sync
│   ├── sync_webfp.py       Wappalyzer signature sync
│   ├── feed_sync_worker.php CLI worker for UI feed sync (non-FPM PHP)
│   ├── feed_sync_cancel.py Cooperative cancel flag (UI “Cancel sync”)
│   └── sources/            Enrichment plugins
│       ├── unifi.py        UniFi controller
│       ├── snmp.py         SNMP polling
│       ├── dhcp.py         Generic DHCP lease import
│       ├── dns_logs.py     Generic DNS log import
│       ├── firewall_logs.py Generic firewall log import
│       └── stubs.py        Plugin stubs (Cisco, Meraki, etc.)
├── public/
│   └── index.php           Single-page web UI
├── sql/
│   └── schema.sql          Database schema
├── docs/
│   └── DEVICE_IDENTITY.md  Device vs address model + API notes
├── setup.sh                       First-time installation script
├── deploy.sh                      Deploy updates to /opt/surveytrace
├── surveytrace-daemon.service     systemd: scanner worker
└── surveytrace-scheduler.service  systemd: cron scheduler
```

## Scan Profiles

| Profile | Description | Safe for IoT | Safe for OT |
|---------|-------------|:------------:|:-----------:|
| IoT Safe | Passive only — ARP/ICMP, no port scanning | ✅ | ✅ |
| Standard Inventory | Common ports, light banners, CVE correlation | ⚠️ | ❌ |
| Deep Scan | Full nmap -sV, SNMP, all ports — requires confirmation | ❌ | ❌ |
| Full TCP | All TCP ports (-p-) with service detection, high coverage, slower | ❌ | ❌ |
| Fast Full TCP | All TCP ports (-p-) with lighter/faster service detection | ❌ | ❌ |
| OT Careful | Passive only, 2pps max rate | ✅ | ✅ |

## Discovery Modes

| Mode | Description | Use When |
|------|-------------|----------|
| Auto | ARP for same-subnet, ICMP/TCP ping scan for routed | Default — works for most networks |
| Routed | ICMP/TCP ping scan only — no ARP | Scanning across routers |
| Force (-Pn) | Scan all IPs regardless of ping response | Hosts with ICMP blocked (UFW etc.) |

## UI Modes and Theme

- **Theme toggle** (top bar): `Dark`, `Light`, `Auto` (follows system `prefers-color-scheme`)
- **Executive view** (Dashboard): optimized presentation mode for briefing screens
  - focuses on dashboard content
  - uses larger typography and cleaner dashboard spacing

## Enrichment Sources

| Source | Description | Status |
|--------|-------------|--------|
| UniFi | Pulls client list, hostnames, device info from UniFi controller | ✅ Available |
| SNMP | Polls routers/switches for ARP tables plus LLDP/CDP neighbor hints | ✅ Available |
| DHCP Leases (generic) | Imports hostnames/MACs from router DHCP lease files (dnsmasq/ISC/JSON) | ✅ Available |
| DNS Logs (generic) | Imports host hints from DNS query logs (Pi-hole/dnsmasq/BIND/JSON) | ✅ Available |
| Firewall Logs (generic) | Imports host hints from firewall events (KV/JSON/JSONL) | ✅ Available |
| Cisco DNA Center | Network device inventory | 🔧 Stub |
| Cisco Meraki | Cloud-managed network devices | 🔧 Stub |
| Juniper Mist | Cloud-managed wireless | 🔧 Stub |
| Infoblox | IPAM and DNS data | 🔧 Stub |
| Palo Alto | Firewall user/device data | 🔧 Stub |

## Roadmap

### Completed (summary)
- **Phase 5 — Device identity** — Logical **`devices`** linked from **`assets`**; scanner + migrations; Devices UI; **`POST /api/devices.php`** merge (logged to **`scan_log`**). Details: **`docs/DEVICE_IDENTITY.md`**. *Not built:* un-merge, split/reassign assets, findings-by-device filter, `device_identifiers` table (optional follow-ons).

### Upcoming
- **Phase 6 — Identity & access (OIDC SSO, local MFA, RBAC)** — **OIDC** for IdP-backed sign-in; **local authentication** (retain or evolve **`basic`** / **`session`**) with optional **MFA** for deployments that skip SSO: **TOTP** (RFC 6238) and **one-time recovery codes** (hashed at rest, single-use, regenerable) so users can regain access without SSO; **WebAuthn** / **FIDO2** (including **passkeys** or roaming security keys) as a **possible** addition if scope and packaging (e.g. Composer + a vetted library) allow — not a fixed commitment in the first cut; **RBAC** with app-defined roles (e.g. full admin, scan operator, read-only inventory, auditor) mapped from IdP **groups/claims** when using SSO and **assigned in-app** for local users; consistent enforcement for **PHP API routes** and UI; **audit attribution** (who queued a scan, changed settings, merged devices). Design so **Phase 7** collector tokens, schedule ownership, and future integrations reuse the same permission checks rather than a parallel auth model.
- **Phase 7 — Collector architecture** — `collectors` table; registration + API token auth (scopes informed by **Phase 6** when RBAC is enabled); **`collector_checkin.php`**, **`collector_jobs.php`**, **`collector_submit.php`**; **`collector_agent.py`** for remote sites; management UI (status, last seen, schedule assignment); per-collector rate limits; health monitoring; first remote deployment (e.g. GVSU). **Processing model:** collectors upload scan result payloads/artifacts to the master server; master persists them to an ingest queue/file store; one/few worker processes apply them into assets/findings/history and run fingerprint/CVE enrichment asynchronously (idempotent, chunked submissions, retry-safe).
- **Phase 8**: Change detection — alerts on new assets, port changes, new CVEs
- **Phase 9**: Asset lifecycle — stale/active/retired status, auto-retire
- **Phase 10**: CVE improvements — per-finding evidence, confidence levels, risk scoring
- **Phase 11**: Baselines and reporting — snapshot comparisons, scheduled reports
- **Phase 12**: Integrations — Splunk, TrueNAS, Proxmox, syslog
- **Phase 13**: UI polish — asset timeline, bulk operations, fingerprint pattern editor; **scan history UX** — pagination or cursor search beyond the current **200**-row cap, **date** and **status** filters, **persisted query** (URL or session) for deep links to filtered results, and **CSV export** of the filtered history list; **frontend modularization (possible)** — split the growing `public/index.php` into maintainable modules (or build-step bundles) to reduce merge conflicts and make feature phases safer to ship.

## License

MIT License

## Author

Greg Vedders — [greg@vedders.com](mailto:greg@vedders.com) — [gregvedders.com](https://gregvedders.com)
