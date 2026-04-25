# SurveyTrace

A self-hosted network asset discovery and inventory platform for homelab and small business environments.

## Features

- **Active scanning** — ARP sweep, ICMP ping, TCP SYN discovery, nmap banner/service detection
- **Passive discovery** — ARP sniff, mDNS/Bonjour service type detection
- **HTTP title grabbing** — identifies self-hosted services by page title (Portainer, Grafana, Jellyfin, ~80 others)
- **CVE correlation** — matches detected CPEs against a local NVD database (no cloud API required)
- **Scan profiles** — IoT Safe, Standard Inventory, Deep Scan, OT Careful
- **Job queue** — multiple queued scans with priority, auto-retry, and per-job progress
- **Scheduling** — cron-based scheduled scans with timezone support
- **Enrichment** — UniFi controller integration, SNMP, extensible source plugins
- **Asset fingerprinting** — OUI lookup, hostname patterns, port profiles, banner analysis
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
│   ├── enrichment.php      Enrichment source management
│   ├── dashboard.php       Dashboard stats
│   └── export.php          Asset export
├── daemon/                 Python background services
│   ├── scanner_daemon.py   Main scan worker
│   ├── scheduler_daemon.py Cron scheduler
│   ├── fingerprint.py      Asset classification engine
│   ├── profiles.py         Scan profile definitions
│   ├── sync_nvd.py         NVD database sync
│   └── sources/            Enrichment plugins
│       ├── unifi.py        UniFi controller
│       ├── snmp.py         SNMP polling
│       └── stubs.py        Plugin stubs (Cisco, Meraki, etc.)
├── public/
│   └── index.php           Single-page web UI
├── sql/
│   └── schema.sql          Database schema
├── setup.sh                First-time installation script
├── deploy.sh               Deploy updates to /opt/surveytrace
└── surveytrace-*.service   systemd service units
```

## Scan Profiles

| Profile | Description | Safe for IoT | Safe for OT |
|---------|-------------|:------------:|:-----------:|
| IoT Safe | Passive only — ARP/ICMP, no port scanning | ✅ | ✅ |
| Standard Inventory | Common ports, light banners, CVE correlation | ⚠️ | ❌ |
| Deep Scan | Full nmap -sV, SNMP, all ports — requires confirmation | ❌ | ❌ |
| OT Careful | Passive only, 2pps max rate | ✅ | ✅ |

## Discovery Modes

| Mode | Description | Use When |
|------|-------------|----------|
| Auto | ARP for same-subnet, ICMP/TCP ping scan for routed | Default — works for most networks |
| Routed | ICMP/TCP ping scan only — no ARP | Scanning across routers |
| Force (-Pn) | Scan all IPs regardless of ping response | Hosts with ICMP blocked (UFW etc.) |

## Enrichment Sources

| Source | Description | Status |
|--------|-------------|--------|
| UniFi | Pulls client list, hostnames, device info from UniFi controller | ✅ Available |
| SNMP | Polls routers/switches for ARP tables and interface data | ✅ Available |
| Cisco DNA Center | Network device inventory | 🔧 Stub |
| Cisco Meraki | Cloud-managed network devices | 🔧 Stub |
| Juniper Mist | Cloud-managed wireless | 🔧 Stub |
| Infoblox | IPAM and DNS data | 🔧 Stub |
| Palo Alto | Firewall user/device data | 🔧 Stub |

## Roadmap

### In Progress
- Phase 3: Scheduling (complete — polish remaining)
- Phase 4: Discovery improvements (complete — DHCP/DNS import remaining)

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
