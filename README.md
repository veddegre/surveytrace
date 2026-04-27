# SurveyTrace

A self-hosted network asset discovery and inventory platform for general-purpose networks.

## Features

- **Active scanning** — ARP sweep, ICMP ping, TCP SYN discovery, nmap banner/service detection
- **Passive discovery** — ARP sniff, mDNS/Bonjour service type detection
- **HTTP title grabbing** — identifies self-hosted services by page title (Portainer, Grafana, Jellyfin, ~80 others)
- **CVE correlation** — matches detected CPEs against a local NVD database (no cloud API required)
- **Feed sync** — scheduled IEEE OUI + Wappalyzer signature imports for fresher fingerprinting
- **Manual feed sync UX** — in-app sync progress/status indicators, output viewer, and single-sync guard
- **Scan profiles** — IoT Safe, Standard Inventory, Deep Scan, Full TCP, Fast Full TCP, OT Careful
- **Job queue** — multiple queued scans with priority, auto-retry, and per-job progress
- **Scheduling** — cron-based scheduled scans with timezone support
- **Scan history** — per-run history, duration, summary snapshot, and detail view
- **UI themes** — Dark / Light / Auto mode with persistent preference
- **Executive dashboard view** — presentation-focused dashboard mode
- **Enrichment** — UniFi controller integration, SNMP, DHCP lease import, DNS log import, firewall log import, extensible source plugins
- **Asset fingerprinting** — OUI lookup, hostname patterns, port profiles, banner analysis, Proxmox node-name extraction
- **Vulnerability tracking** — CVSS scoring, severity filtering, CSV/JSON export
- **Multi-subnet** — auto, routed, and force (-Pn) discovery modes

## Requirements

- Ubuntu 22.04+ or Debian 12+
- Python 3.10+
- PHP 8.1+ with SQLite3 extension
- Apache 2.4+
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

`deploy.sh` copies updated files to `/opt/surveytrace` and restarts both daemons automatically.

## NVD Database Setup

```bash
# Initial download (~1GB, 5-10 minutes)
sudo -u surveytrace /opt/surveytrace/venv/bin/python3 \
    /opt/surveytrace/daemon/sync_nvd.py

# Weekly update (add to crontab)
0 3 * * 0 surveytrace /opt/surveytrace/venv/bin/python3 \
    /opt/surveytrace/daemon/sync_nvd.py --recent
```

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
- Captures script stdout/stderr in the “View last output” modal

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
