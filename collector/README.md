# SurveyTrace Collector Guide

This guide covers installing and operating a remote SurveyTrace collector host.

Collectors run local discovery/scanning in remote networks and submit chunked results to the master server for centralized processing and enrichment.

## Prerequisites

- Debian/Ubuntu host with outbound HTTPS access to the SurveyTrace master.
- Root/sudo access on the collector host.
- SurveyTrace master reachable at a URL like `https://surveytrace.example.com`.
- Admin access in SurveyTrace UI to generate the collector install token.

## Collector system requirements

- OS: Debian 12+ or Ubuntu 22.04+ (systemd-based)
- CPU: 2 vCPU minimum (4 vCPU recommended for heavier scan overlap)
- RAM: 2 GB minimum (4 GB recommended for larger subnets / multiple concurrent jobs)
- Disk: 8 GB minimum free space (20 GB recommended for logs, updates, and scan artifacts)
- Network: stable outbound HTTPS (`443/tcp`) to the master URL; no inbound ports required
- Privileges: run setup as root/sudo; runtime uses capture capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`) for passive/local parity discovery

Notes:

- Collectors do **not** need direct internet access for CVE/AI enrichment; that work runs on master ingest.
- Actual scan runtime depends on profile, host count, latency, and job concurrency (`max_jobs`).

### Quick sizing guide (per collector)

| Approx active hosts in site scope | Recommended collector size | Suggested `max_jobs` |
|---|---|---|
| Up to 250 | 2 vCPU / 2 GB RAM | 1 |
| 250-1000 | 4 vCPU / 4 GB RAM | 1-2 |
| 1000-3000 | 8 vCPU / 8 GB RAM | 2-3 |
| 3000+ | 8+ vCPU / 16+ GB RAM (or split by subnet/site) | 2-4 |

Use conservative concurrency first, then raise `max_jobs` only after validating scan duration and network impact on that site.

## 1) Generate install token on master

On the master UI:

1. Go to `Settings`.
2. Open `Collector setup`.
3. Click `Generate token` (or paste/save a token manually).
4. Copy the token.

The install token is used only for first-time collector registration.

## 2) Install collector runtime

From a checkout of this repository on the collector host:

```bash
sudo bash collector/setup.sh
```

This installs dependencies, creates `/opt/surveytrace`, writes systemd service `surveytrace-collector`, and creates:

- `/etc/surveytrace/collector.json`

## 3) Configure collector

Edit `/etc/surveytrace/collector.json`:

```json
{
  "server_base_url": "https://surveytrace.example.com",
  "install_token": "PASTE_FROM_MASTER_UI",
  "name": "collector-site-1",
  "site_label": "Site 1",
  "version": "collector-agent-parity",
  "max_jobs": 2,
  "poll_interval_sec": 20
}
```

Required:

- `server_base_url`
- `install_token`

Recommended:

- unique `name`
- descriptive `site_label`

## 4) Start / register collector

```bash
sudo systemctl restart surveytrace-collector
sudo systemctl status surveytrace-collector --no-pager
```

On first successful registration, the agent receives and stores a bearer token in the same config file as `collector_token`.

## 5) Verify in master UI

In SurveyTrace:

- Open `Collectors` tab.
- Confirm collector appears online.
- Optionally:
  - set allowed CIDR ranges
  - assign schedules
  - rotate/revoke token

## Updating collector code

After pulling new code on collector host:

```bash
bash collector/deploy.sh
```

## Hardening

Apply baseline hardening:

```bash
sudo bash collector/hardening.sh
```

## Notes

- Scans are scheduled through the master `scan_schedules` pipeline (`collector_id` decides execution site).
- If collector allowed CIDRs are configured on master, out-of-scope targets are blocked by policy checks.
- CVE and AI enrichment run on master ingest workers, not on remote collectors.
