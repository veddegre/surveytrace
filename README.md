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
- **Scan history** — per-run history, duration, summary snapshot, and detail view
- **UI themes** — Dark / Light / Auto mode with persistent preference
- **Executive dashboard view** — presentation-focused dashboard mode
- **System health** — **System** sidebar tab and `GET /api/health.php` (data dir, free space only from `df`—`Available` 1K-blocks × 1024, `LC_ALL=C` + `awk`; PHP `disk_free_space` is not used, DB sizes via `stat`/`filesize` vs PHP, optional systemd, scan queue, last feed job)
- **Enrichment** — optional Phase 3b metadata from controllers, SNMP, DHCP/DNS/firewall log imports, and other pluggable sources; per-scan source selection on the Scan tab (omit = all enabled sources)
- **Asset fingerprinting** — OUI lookup, hostname patterns, port profiles, banner analysis, Proxmox node-name extraction
- **Vulnerability tracking** — CVSS scoring, severity filtering, CSV/JSON export
- **Multi-subnet** — auto, routed, and force (-Pn) discovery modes

## Requirements

- Ubuntu 22.04+ or Debian 12+
- Python 3.10+
- PHP 8.1+ with SQLite3 extension
- Apache 2.4+ (or another PHP-capable web stack; **PHP-FPM** is recommended so long-running feed sync can return immediately to the browser)
- nmap
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
sudo mkdir -p /opt/surveytrace/{daemon,api,public,sql,data}
sudo cp -r daemon/ api/ public/ sql/ /opt/surveytrace/
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

- **`api/`** — all HTTP endpoints used by the UI, including `feeds.php`, **`feed_sync_lib.php`** (shared by `feeds.php` and `daemon/feed_sync_worker.php`), `scan_history.php`, `settings.php`, etc.
- **`daemon/`** — scanner, scheduler, fingerprint engine, enrichment `sources/`, **`feed_sync_worker.php`** + **`feed_sync_cancel.py`** (UI cancel / cooperative stop), and the `sync_*.py` feed scripts
- **`public/`** — `index.php` and `css/app.css`
- **`sql/schema.sql`** — reference copy for new installs (existing DBs are migrated by the app on startup)

It then restarts `surveytrace-daemon` and `surveytrace-scheduler`.

**Feed sync from the browser:** Under **PHP-FPM**, sync runs in the same request after `fastcgi_finish_request()`. Under **Apache `mod_php`**, the API spawns `php daemon/feed_sync_worker.php …` in the background, which requires `exec()` not to be in `disable_functions`, and requires `feed_sync_worker.php` to be present on disk (deploy copies it). NVD runs with **`--recent`** from PHP so the job matches weekly cron behavior and stays within typical HTTP worker limits.

SQLite schema changes apply automatically on next API or daemon startup (`ALTER TABLE` migrations); fresh installs use `sql/schema.sql` with a complete `scan_jobs` definition.

## Changelog

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

- **`basic`** (default): browser HTTP Basic Auth (`admin` + password). Each API request may trigger a Basic challenge until credentials are stored for the site.
- **`session`**: login via `POST /api/auth.php?login=1` with `admin` credentials; the UI uses a session cookie after login.

To switch modes, set `auth_mode` in the `config` table to `basic` or `session` (defaults to `basic` in `sql/schema.sql`); there is no separate toggle in the Settings UI yet. Session idle timeout is configurable under **Settings** (`session_timeout_minutes`).

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
│   ├── scan_history.php    Scan run history + per-run detail
│   ├── enrichment.php      Enrichment source management
│   ├── dashboard.php       Dashboard stats
│   ├── feeds.php           Manual feed sync trigger (Settings UI)
│   ├── feed_sync_lib.php   Feed sync resolution + exec (used by feeds.php + worker)
│   ├── settings.php        Session timeout, safe ports, NVD API key (server-side)
│   ├── auth.php            Session login/status endpoint
│   ├── logout.php          Session logout endpoint
│   └── export.php          Asset export
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

### Upcoming
- **Phase 5**: MAC-first asset identity — track devices across IP changes
- **Phase 6**: Collector architecture — distributed agents for multi-site scanning
- **Phase 7**: Change detection — alerts on new assets, port changes, new CVEs
- **Phase 8**: Asset lifecycle — stale/active/retired status, auto-retire
- **Phase 9**: CVE improvements — per-finding evidence, confidence levels, risk scoring
- **Phase 10**: Baselines and reporting — snapshot comparisons, scheduled reports
- **Phase 11**: Integrations — Splunk, TrueNAS, Proxmox, syslog
- **Phase 12**: UI polish — asset timeline, bulk operations, fingerprint pattern editor

## License

MIT License

## Author

Greg Vedders — [greg@vedders.com](mailto:greg@vedders.com) — [gregvedders.com](https://gregvedders.com)
