# Getting Started

[← Back to Documentation](README.md)

## What SurveyTrace is

- SurveyTrace is a security and asset visibility platform for running scans, enriching asset context, and reviewing risk in one interface.
- It is designed for operators who need both:
  - **Current inventory visibility** — what exists right now
  - **Historical scan evidence** — what changed over time

## Master vs Collector

- **Master node**
  - Hosts the web UI, API, database, scheduler, and core workers.
  - Central control point for scans, assets, enrichment, and reporting.
  - Typically installed once per environment.

- **Collector node**
  - Optional remote scan worker.
  - Used for remote networks, segmented environments, or distributed scan load.
  - Sends results back to the master.

## Installation summary

### Install master

```bash
sudo ./setup.sh
```

This will:

- create the `surveytrace` service user
- install systemd services
- install PHP packages for the API and workers, including **`php-xml`** (**XMLReader**) and **`php-bz2`** (Canonical Ubuntu OVAL **`.xml.bz2`**) for advisory fetch/convert and deploy-time selftests
- initialize the database
- set permissions under `/opt/surveytrace`
- prepare the web interface
- run post-install validation checks

### Deploy updates

```bash
sudo ./deploy.sh
```

Use this after pulling updates. It will:

- update application files
- validate permissions and required files
- verify services and workers
- restart services as needed

### Install optional collector

```bash
cd collector
sudo ./setup.sh
```

This will:

- install the collector service
- create `/etc/surveytrace/collector.json`
- configure the collector runtime
- run collector-specific validation checks

## Post-install verification

After installing the master, verify everything is running.

### Check scheduler

```bash
systemctl status surveytrace-scheduler
```

Expected:

- service is `active (running)`
- no repeated errors

### Check web UI

Open:

```text
http://<server-ip>/
```

Expected:

- dashboard loads
- no API errors in the browser console

### Check database exists

```bash
ls -l /opt/surveytrace/data/surveytrace.db
```

Expected:

- file exists
- ownership is appropriate for `surveytrace:www-data`
- service can read/write it

### Check logs

```bash
journalctl -u surveytrace-scheduler -n 50
```

Use this when scans, enrichment, or scheduled jobs do not behave as expected.

## First steps

### 1. Start your first scan

- Go to **Scan control**.
- Select a scan profile.
- Enter a target network or host.
- Click **Start scan**.

### 2. Monitor scan progress

- Open **Scan history**.
- Watch jobs move from queued to running to completed.
- Open scan details to review job output.

### 3. Review discovered assets

- Open **Assets**.
- Review:
  - IP addresses
  - hostnames
  - open ports
  - classifications
  - findings

### 4. Run enrichment

- Open **Enrichment**.
- Configure and sync supported integrations such as Zabbix.
- Review matches.
- Apply trusted matches or scope rules.

### 5. Review reports

- Open **Reports & Analysis**.
- Choose report mode:
  - **Job scope** for historical scan-job reporting
  - **Inventory scope** for current asset-state reporting

## What to expect

After the first successful scan:

- assets appear in **Assets**
- scan history contains the completed job
- reports have job-based data for completed scans
- enrichment can add external context after sync
- inventory-scope reports can show current grouped assets even when job-scope reports have no history

## Common issues

### Web UI loads but shows no data

Likely cause:

- no scans have completed yet

What to do:

- start a scan from **Scan control**
- check **Scan history**

### Scan does not start

Check:

```bash
systemctl status surveytrace-scheduler
journalctl -u surveytrace-scheduler -n 50
```

Also verify:

- install/deploy validation passed
- permissions under `/opt/surveytrace` are correct

### No assets appear after scan

Check:

- scan job completed successfully
- target was reachable
- scan profile was appropriate for the target

### Reports show no data

Likely cause:

- selected **Job scope** has no completed scan jobs

What to do:

- switch to **Inventory scope**, or
- run a scan using the intended job scope

## Next steps

- Configure integrations → [Integrations](integrations.md)
- Add API keys → [API Keys](api-keys.md)
- Run enrichment → [Enrichment](enrichment.md)
- Understand scope behavior → [Concepts](concepts.md)

---

See also:
- [Documentation home](README.md)