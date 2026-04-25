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
├── daemon/                 Python background services
│   ├── scanner_daemon.py   Main scan worker
│   ├── scheduler_daemon.py Cron scheduler
│   ├── fingerprint.py      Asset classification
│   ├── profiles.py         Scan profile definitions
│   ├── sync_nvd.py         NVD sync
│   └── sources/            Enrichment plugins
├── public/
│   └── index.php           Single-page web UI
├── sql/
│   └── schema.sql          Database schema
└── surveytrace-*.service   systemd units
```

## Scan Profiles

| Profile | Description | Safe for IoT |
|---------|-------------|--------------|
| IoT Safe | Passive only — ARP/ICMP, no port scanning | ✅ |
| Standard Inventory | Common ports, light banners, CVE correlation | ⚠️ |
| Deep Scan | Full nmap -sV, SNMP, all ports | ❌ |
| OT Careful | Passive only, 2pps max | ✅ |

## Discovery Modes

| Mode | Description |
|------|-------------|
| Auto | ARP for same-subnet, ping scan for routed |
| Routed | ICMP/TCP ping only — no ARP |
| Force (-Pn) | Scan all IPs regardless of ping (firewalled hosts) |

## Roadmap

- Distributed collectors (multi-site)
- MAC-first asset identity
- Passive DHCP/DNS sources
- Change detection and alerting
- Baselines and reporting

## License

MIT License

## Author

Greg Vedders — [greg@vedders.com](mailto:greg@vedders.com) — [gregvedders.com](https://gregvedders.com)
