# SurveyTrace

A self-hosted network asset discovery and inventory platform for general-purpose networks.

## Table of Contents

- [Deployment Models](#deployment-models)
- [Setup and deploy (master vs collector)](#setup-and-deploy-master-vs-collector)
- [Name and Purpose](#name-and-purpose)
- [Features](#features)
- [Requirements](#requirements)
- [Settings - AI Enrichment (Optional)](#settings---ai-enrichment-optional)
- [Reporting API](#reporting-api)
- [SQLite locking and concurrency](#sqlite-locking-and-concurrency)
- [Asset lifecycle](#asset-lifecycle)
- [Quick Start](#quick-start)
- [Manual Installation](#manual-installation)
- [Updating / Deploying Changes](#updating--deploying-changes)
- [Collector Deployment (Multi-System)](#collector-deployment-multi-system)
- [Changelog](#changelog)
- [NVD Database Setup](#nvd-database-setup)
- [Roadmap](#roadmap)
- [License](#license)
- [Author](#author)

## Deployment Models

SurveyTrace supports both single-host and multi-system deployments:

- **Single-host**: scanner, scheduler, web UI, and data store run on one server.
- **Multi-system (with collectors)**: one master server handles UI/scheduling/ingest while one or more remote collectors run scans in their local networks and submit results back to master.

Use collectors when you need local-segment visibility (ARP/mDNS/passive signals) in remote sites without exposing those networks directly to the master scanner.

## Setup and deploy (master vs collector)

SurveyTrace distinguishes a **full server (master)** install from a **collector-only** node. The repo root scripts guide you so the wrong stack is not applied to the wrong host.

### First-time install (`setup.sh`)

From the cloned repo:

```bash
cd surveytrace
sudo bash setup.sh
```

**Interactive (normal terminal):** you are prompted to choose:

1. **Full SurveyTrace server** — web UI, PHP API, SQLite, scanner + scheduler daemons, feed sync, etc. (same behavior as always).
2. **Collector only** — minimal Python + `surveytrace-collector` agent for a remote site; continues into `collector/setup.sh`.

**Non-interactive** (no TTY: some GUIs, automation, `ssh` without `-t`): the menu is skipped. Set the install type explicitly:

```bash
# Full server
SURVEYTRACE_SETUP=master sudo bash setup.sh

# Collector node
SURVEYTRACE_SETUP=collector sudo bash setup.sh
```

Accepted values for `SURVEYTRACE_SETUP` include `master` / `full` / `server` and `collector` / `agent` (case-insensitive).

### Updating from git (`deploy.sh`)

After `git pull`, use the **same** command on the master and on collector nodes (from the repo directory):

```bash
bash deploy.sh
```

`deploy.sh` inspects the host (marker file + expected paths under `/opt/surveytrace`) and either:

- syncs the **full application** (API, UI, daemons, schema reference, systemd hooks) and restarts master services, or
- delegates to **`collector/deploy.sh`** on collector-only hosts (daemon files + schema reference + `surveytrace-collector` restart).

`deploy.sh` refuses to run if first-time **setup** does not appear to have completed (missing venv, API/DB paths on master, or collector agent/config on collectors). The error text points back to `setup.sh` / `collector/setup.sh`.

**Overrides (rare):**

| Variable | Purpose |
|----------|---------|
| `SURVEYTRACE_DEPLOY=master` or `collector` | Force deploy mode after verifying that install type’s “setup complete” checks pass. |
| `SURVEYTRACE_SKIP_INSTALL_ROLE_CHECK=1` | Emergency only: infer mode from filesystem only and ignore `.install_role` vs chosen mode mismatches. |

### Install marker file (`data/.install_role`)

Current `setup.sh` / `collector/setup.sh` write a one-line marker (not in git):

| Path | Content | Meaning |
|------|---------|---------|
| `/opt/surveytrace/data/.install_role` | `master` | Full server install |
| `/opt/surveytrace/data/.install_role` | `collector` | Collector-only install |

`deploy.sh` uses this together with on-disk checks to choose full vs collector sync.

### Legacy installs (add the marker)

If the host was set up **before** this marker existed, detection still uses paths (e.g. presence of `/opt/surveytrace/api/db.php` and `data/surveytrace.db` on master). To **lock** behavior and match new scripts exactly, create the marker after confirming the machine’s role:

**Master server** (typical ownership matches `setup.sh`: app user + `www-data` on `data/`):

```bash
printf '%s\n' master | sudo tee /opt/surveytrace/data/.install_role >/dev/null
sudo chown surveytrace:www-data /opt/surveytrace/data/.install_role
sudo chmod 660 /opt/surveytrace/data/.install_role
```

**Collector-only node** (typical ownership: `surveytrace:surveytrace` on the install tree per `collector/setup.sh`):

```bash
printf '%s\n' collector | sudo tee /opt/surveytrace/data/.install_role >/dev/null
sudo chown surveytrace:surveytrace /opt/surveytrace/data/.install_role
sudo chmod 660 /opt/surveytrace/data/.install_role
```

If your site uses a non-default install user or group, match ownership to other files in `/opt/surveytrace/data/`.

## Name and Purpose

SurveyTrace combines two ideas at the core of network visibility.

Survey refers to systematically examining an area to map what exists within it, similar to how a land surveyor documents every boundary and structure on a property. Trace refers to following connections to their source and keeping a record of what was found and when.

Together, the name describes exactly what the tool does: it surveys your network to discover what is there, then traces those assets over time so you can understand how your environment changes.

**Current release (see `VERSION` and `RELEASE_NOTES.md`):** SurveyTrace ships **snapshot reporting** (compare, trends, compliance, scheduled report artifacts), **named scan scopes** with scoped baselines and safer auto-drift rules, **change detection and CVE triage**, **asset lifecycle** (stale/retired from coverage misses), and **Integrations** (admin-configured push targets with manual test/sample, read-only **pull** APIs with **per-integration bearer tokens** only, and starter Splunk/Grafana assets). Automatic outbound fan-out of scan or report events to integrations is **not** enabled yet—that remains on the [roadmap](#roadmap).

## Features

- **Active scanning** — ARP sweep, ICMP ping, TCP SYN discovery, nmap banner/service detection
- **Passive discovery** — ARP sniff, mDNS/Bonjour service type detection
- **HTTP title grabbing** — identifies self-hosted services by page title (Portainer, Grafana, Jellyfin, ~80 others)
- **CVE correlation** — matches detected CPEs against a local NVD database (no cloud API required); optional NIST API key via **Settings** or `NVD_API_KEY` for faster NVD sync rate limits
- **AI providers** — **Settings → AI enrichment (optional)**: **Ollama** (local), **OpenAI**, **Anthropic Claude**, **Google Gemini**, or **Open WebUI** (OpenAI-compatible `POST …/api/chat/completions` on your instance). Keys and base URL live in SQLite **or** env: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` / `GOOGLE_API_KEY`, `OPENWEBUI_BASE_URL`, `OPENWEBUI_API_KEY`. The **same** provider drives **scanner per-host enrichment** (when enabled), **per-run scan summaries**, and **operator AI** (host CVE triage, explain host, refresh scan summary via `POST /api/ai_actions.php`).
- **Feed sync** — scheduled IEEE OUI + Wappalyzer signature imports for fresher fingerprinting
- **Manual feed sync UX** — in-app sync progress/status indicators, output viewer, and single-sync guard
- **Scan profiles** — IoT Safe, Standard Inventory, Deep Scan, Full TCP, OT Careful (see **Scan Profiles** below: **Deep Scan** uses a large fixed port list; **Full TCP** is the selectable profile for an all-TCP **`-p-`** sweep on LAN — use smaller targets or Standard/Deep Scan over **routed** / high-latency paths, where a full sweep is slow and easy to time out)
- **Host rescan** — from Assets host detail, scan editors get a modal with the same levers as the Scan tab: profile, phases, rates, discovery mode, exclusions, and per-run enrichment toggles; the Scan tab syncs after a successful queue
- **Job queue** — multiple queued scans with priority, auto-retry, and per-job progress
- **Scheduling** — cron-based scheduled scans with timezone support; schedule editor mirrors manual scan options (phases, rate limits, priority, discovery mode, per-run enrichment subset, high-impact profile confirmation)
- **Scan history** — dedicated **Scan history** sidebar page: job queue, finished runs, Active/Trash views, and a debounced filter by **scan label**, target CIDR, or job id (`GET /api/scan_history.php` with **`q`**, up to **`limit=200`**; see `api/scan_history.php`). From a run’s **Details** modal, click a catalogued host row to jump to **Devices** (when `device_id` is set) or **Assets** host detail by IP. **Scan control** remains the page to queue new jobs.
- **UI themes** — Dark / Light / Auto mode with persistent preference
- **Executive dashboard view** — presentation-focused dashboard mode
- **System health** — **System** sidebar tab: live operational summary (background services, disk, databases, scan queue, feed sync) via `GET /api/health.php` (read-only, no config changes)
- **Database backups** — scheduler-driven SQLite backups via `daemon/backup_db.sh`, configurable in **Settings** (enable, cron, retention days, keep-count)
- **On-demand DB snapshot** — admin button in **Settings** can run `backup_db.sh` immediately before risky maintenance (e.g., bulk scan cleanup)
- **Enrichment** — optional metadata from controllers, SNMP, DHCP/DNS/firewall log imports, and other pluggable sources during scans; per-scan source selection on the Scan tab (omit = all enabled sources)
- **Collector architecture (MVP + parity runner)** — remote collectors run assigned scans from the same schedule system, upload chunked results to master, and use centralized CVE/AI enrichment.
- **Change detection** — in-app **Change alerts** for new hosts, material port deltas, and CVE lifecycle (new / active / mitigated / accepted / reopened); **`GET/POST /api/change_alerts.php`** and lifecycle-aware **`findings.php`** actions.
- **Explainable CVE triage** — per-finding **confidence**, **risk score**, **detection method**, **provenance**, and **evidence** (scanner + collector); surfaced on **Vulnerabilities** and host detail; export columns on **`findings_export.php`**.
- **CVE intelligence** — **`cve_intel`** table (CISA **KEV**, **FIRST EPSS**, **OSV** ecosystem hints); **`daemon/sync_cve_intel.py`** and Settings **Sync CVE intel** / full **Sync all feeds**; joined on **`findings.php`** as structured **`intel`** (useful across Linux, Windows, **macOS**, **Hyper-V**, containers, and mobile platforms where OSV/NVD overlap).
- **Asset lifecycle** — **`assets.lifecycle_status`** (**`active`**, **`stale`**, **`retired`**) driven by **expected scan coverage** (IP in job **`target_cidr`** vs presence in **`scan_asset_snapshots`** for that job), not idle time since **`last_seen`**. **`change_alerts`** for stale/retired/reactivated; optional **owner / business_unit / criticality / environment** tagging; **`identity_confidence`** fields reserved for provenance scoring. See **[Asset lifecycle](#asset-lifecycle)**.
- **Baselines & reporting** — Reuses existing **`scan_asset_snapshots`** / **`scan_finding_snapshots`** (no duplicate snapshot tables). **`GET /api/reporting.php`** (`compare`, **`compare_summary`**, `summary`, `trends`, **`trends_summary`**, `compliance`, `baseline`, `artifacts`, **`artifact_summary`**, admin **`artifact_payload_preview`**, **`compare_debug`** / **`baseline_debug`**) plus **`POST …?action=set_baseline`**; global baseline in **`config.phase13_baseline_job_id`** and **`scan_jobs.is_baseline`**. **`scan_schedules.schedule_action`**: **`scan`** (default) or **`report`**; report schedules run **`api/reporting_cli.php`** in a **subprocess** (separate DB connection, no scan **`queued`/`running`** row). Invalid baseline config is ignored safely for diffs. Structured **`SurveyTrace.reporting`** JSON lines in **`error_log`** for compares, baseline resolution, materialize, and report payloads. The **Reports & Analysis** sidebar tab uses **slim summary actions** by default (no full stored payloads in the list path); **Scan history** adds bounded inline **SVG line charts** from **`trends_summary`** plus tables. See **[Reporting API](#reporting-api)** and **`RELEASE_NOTES.md`** (0.13.0). CSV export remains a follow-up.
- **Asset fingerprinting** — OUI lookup, hostname patterns, port profiles, banner and HTTP-title analysis; **Proxmox VE** node-name extraction; **VMware ESXi / vSphere / vCenter** and **Microsoft Hyper-V** signals; mDNS hints for **Apple** mobile/desktop classes where visible
- **AI enrichment (optional)** — When **Enable AI enrichment** is on and the provider is reachable, the **scanner** may call the model for **ambiguous** hosts (`unk` / borderline `net` vs `srv`, subject to thresholds); the **daemon** can generate a **per-run scan summary**; the **UI** exposes **operator AI** (cached CVE triage, explain host, **Refresh AI summary** on completed jobs). All use the configured provider with conservative apply rules (`ai_conflict_only`, confidence thresholds). See **Settings → AI enrichment** below for every knob.
- **Vulnerability tracking** — CVSS scoring, severity filtering, CSV/JSON export
- **Multi-subnet** — auto, routed, and force (-Pn) discovery modes
- **Device identity** — logical **`devices`** rows with **`assets.device_id`** (stable id per inventory host; merge duplicates via API/UI). See **`docs/DEVICE_IDENTITY.md`**.

## Requirements

- Ubuntu 22.04+ or Debian 12+
- Python 3.10+
- PHP 8.1+ with **SQLite3** and **cURL** extensions (`php-sqlite3`, `php-curl`) — required for Zabbix sync, integration webhooks, and cloud AI HTTP clients
- Apache 2.4+ (or another PHP-capable web stack; **PHP-FPM** is recommended so long-running feed sync can return immediately to the browser)
- nmap
- `samba-common-bin` (for `nmblookup` NetBIOS hostname fallback)
- `qrencode` (for local-only MFA QR rendering)
- 2GB RAM, 10GB disk (NVD database is ~1GB)

### Settings - AI enrichment (optional)

All of these are edited in the web UI (**Settings** card **AI enrichment (optional)**) and stored in SQLite `config` (keys below). Cloud keys and Open WebUI URL may be overridden by the env vars listed in **Features** above.

| Area | Config key / UI control | What it does |
|------|-------------------------|--------------|
| Master | **Enable AI enrichment** → `ai_enrichment_enabled` | Off by default. When off, the scanner records `ai_disabled` and skips model calls. |
| Provider | **Provider** → `ai_provider` | `ollama` \| `openai` \| `anthropic` \| `google` \| `openwebui`. Scanner daemon and operator AI use this choice (Ollama: HTTP to `127.0.0.1:11434`; clouds: respective APIs; Open WebUI: chat completions on your base URL). |
| Model | **Model tag / model id** → `ai_model` | Ollama tag (e.g. `phi3:mini`) or cloud/WebUI model id string. |
| Scanner speed | **AI timeout (ms)** → `ai_timeout_ms` | Per-host scanner inference ceiling (100–5000 ms). |
| Scanner volume | **Max hosts per scan** → `ai_max_hosts_per_scan` | Cap on hosts that run enrichment per job (1–5000). |
| Scanner targeting | **Ambiguous hosts only** → `ai_ambiguous_only` | Default on: only `unk` / `net` / `srv` categories are sent to the model. |
| Scanner apply | **Suggest only (no DB apply)** → `ai_suggest_only` | Log-style only; do not write AI category back to assets. |
| Scanner apply | **Conflict only** → `ai_conflict_only` | Default on: do not apply when the model returns the **same** category as the fingerprint (reduces churn). |
| Scanner apply | **Confidence** / **Net↔srv confidence** → `ai_conf_threshold`, `ai_conf_threshold_net_srv` | Minimum model confidence to apply a category change (stricter for `net`↔`srv` flips). |
| Operator / scan summary | **Operator AI wait (s)** → `ai_operator_ollama_timeout_s` | Max wall clock for **operator AI** and long **PHP** completions (120–3600). Key name is historical: the same cap is applied to **cloud** calls in `api/lib_ai_cloud.php` (curl timeout), not only Ollama. Align web server / FPM timeouts (see Updating / Deploying). |
| Tokens / temperature | **Max gen tokens**, **Temperature** → `ai_operator_ollama_num_predict`, `ai_operator_ollama_temperature` | **Ollama:** `num_predict` / temperature in **generate** options. **Cloud + Open WebUI:** daemon maps these to provider **max_tokens** / **temperature** (`daemon/ai_cloud_client.py`). |
| Ollama-only tuning | **CPU threads**, **Ctx tokens** → `ai_operator_ollama_num_thread`, `ai_operator_ollama_num_ctx` | Sent only to **Ollama** `/api/generate` (ignored for OpenAI / Anthropic / Gemini / Open WebUI). |
| Prompt size | **Banner lines** / related → `ai_operator_prompt_banner_max_lines`, `ai_operator_prompt_banner_val_max`, `ai_operator_prompt_banner_max_chars` | Truncate banners in AI prompts for **scanner and operator** paths (smaller = faster, less context). |
| Admin | **Start/check Ollama**, **Check updates**, model pull | Ollama-only one-shots via `settings.php` (`ai_install_ollama`, `ai_check_updates`, `ai_pull_model`); see **View full Ubuntu setup** for first-time host commands. |

#### External providers (OpenAI, Anthropic, Google Gemini, Open WebUI)

When **`ai_provider`** is not `ollama`, the **scanner daemon** (`daemon/scanner_daemon.py` + **`daemon/ai_cloud_client.py`**) and **operator AI** in PHP (`api/ai_actions.php` + **`api/lib_ai_cloud.php`**) call the vendor HTTP APIs directly (stdlib / curl). **No SurveyTrace cloud proxy** — your keys talk straight to the provider (or to your self-hosted Open WebUI).

| Provider | Credential (DB key / env) | Model field | HTTP surface (implementation) |
|----------|---------------------------|-------------|--------------------------------|
| **OpenAI** | `ai_openai_api_key` or `OPENAI_API_KEY` | OpenAI chat model id (e.g. `gpt-4o-mini`) | `POST https://api.openai.com/v1/chat/completions` |
| **Anthropic** | `ai_anthropic_api_key` or `ANTHROPIC_API_KEY` | Claude model id | `POST https://api.anthropic.com/v1/messages` (`anthropic-version: 2023-06-01`) |
| **Google** | `ai_gemini_api_key` or `GEMINI_API_KEY` / `GOOGLE_API_KEY` | Gemini model id (e.g. `gemini-2.0-flash`) | `POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key=…` |
| **Open WebUI** | `ai_openwebui_base_url` + `ai_openwebui_api_key` or `OPENWEBUI_BASE_URL` + `OPENWEBUI_API_KEY` | Model id **as exposed by that server** (often same string as the backing Ollama tag) | `POST {base}/api/chat/completions` (OpenAI-compatible body; **Bearer** API key from Open WebUI settings) |

**Base URL (Open WebUI):** use the **site origin only** (e.g. `https://chat.example.com`) — **no path**; SurveyTrace appends `/api/chat/completions`.

**Privacy / cost:** scanner enrichment runs **once per eligible host per scan** (capped by **`ai_max_hosts_per_scan`**); operator actions run when an editor uses the buttons. Use **`ai_ambiguous_only`**, **`ai_timeout_ms`**, and prompt size limits to control spend and data sent off-host.

**Scan job line items:** completed jobs show **AI enrichment: attempted N \| applied M** — *attempted* counts hosts that entered the model path; *applied* counts hosts where the stored **category** was changed (`ai_local_inference` may appear on `discovery_sources`).

### VM sizing for local inference (Ollama / Open WebUI on same host)

AI enrichment is optional and off by default. If you run **Ollama** (or models behind Open WebUI) on the SurveyTrace host, use a **compact** model (recommended: `phi3:mini`) and size the VM for inference overhead:

- **Single `/24` homelab run profile** — `4 vCPU`, `8-12 GB RAM`, `64+ GB` disk
- **Multiple `/24` batch runs profile** — `6-8 vCPU`, `12-16 GB RAM`, `80+ GB` disk
- Keep large environments split into `/24` runs and schedule them sequentially on lower-end hosts

Suggested **low-end** defaults (same keys as in the table):

- `ai_model=phi3:mini` (or a smaller cloud model id if not using Ollama)
- `ai_timeout_ms=500-700`
- `ai_max_hosts_per_scan=20` (`/24`) or `60` (multi-`/24` batch host)
- `ai_ambiguous_only=true`

### Ollama updates and maintenance (server shell)

**Note:** Detailed operator runbooks are expected to move to a project **wiki** when it exists; README and in-app copy will link there.

The **Settings → AI enrichment → View full Ubuntu setup** modal only includes **first-time** install and smoke tests so a full copy-paste does not run the installer twice. Use the commands below when you intentionally want to upgrade or tidy the host.

**Upgrade Ollama** (re-running the official install script on Linux is supported upstream):

```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl restart ollama || true
```

**Refresh a model** to the latest blobs for that tag (example: default SurveyTrace model):

```bash
ollama pull phi3:mini
```

**Optional — remove old local models** (replace the tag after checking `ollama list`):

```bash
ollama list
ollama rm <old-model-tag>
```

**Optional — reclaim disk** from unreferenced model data (irreversible; review what you still need):

```bash
ollama prune -f
```

## Asset lifecycle

SurveyTrace tracks each asset’s **lifecycle** separately from “last time we saw any packet.” Lifecycle answers: *given a completed scan that was supposed to cover this IP’s subnet, did we get a row for this host in that run’s evidence?*

### Status values (`assets.lifecycle_status`)

| Status | Meaning |
|--------|---------|
| **`active`** | Default. The asset was observed on a recent ingest path (**scanner** upsert or **collector** artifact apply), or has not yet accumulated a coverage miss. |
| **`stale`** | The asset’s IP lies inside a finished job’s **`target_cidr`**, but that job’s **`scan_asset_snapshots`** did **not** include this host — **one** such miss (**`missed_scan_count` = 1**). |
| **`retired`** | **Two or more** consecutive coverage misses for in-scope jobs (**`missed_scan_count` ≥ 2**). **`retired_at`** is set the first time the row enters retired. |

Supporting columns include **`lifecycle_reason`** (e.g. `observed_in_scan`, `missing_from_expected_scan`, `rediscovered`), **`last_expected_scan_id` / `last_expected_scan_at`**, **`last_missed_scan_id` / `last_missed_scan_at`**, and **`missed_scan_count`**. This is **not** a substitute for monitoring packet loss; it reflects **inventory coverage vs declared scan scope**.

### Business and identity context (optional metadata)

Editable via **`PUT /api/assets.php`** (and the **Edit asset** modal): **`owner`**, **`business_unit`**, **`criticality`** (`low` / `medium` / `high` / `critical`), **`environment`** (free text, default `unknown`). **`identity_confidence`** and **`identity_confidence_reason`** are stored for future enrichment signals (scanner/collector may populate later).

### UI and export

- **Assets** list: filter by **`lifecycle_status`**, lifecycle badge column.
- **`GET /api/export.php`**: CSV and JSON include lifecycle and operator columns (see **`api/export.php`** header order).

## Reporting API

All reporting compares **per-job snapshot tables** only (`scan_asset_snapshots`, `scan_finding_snapshots`). It does **not** diff live `assets` / `findings` rows. Semantics: **job A = reference / baseline**, **job B = current** (newer run).

### Reports & Analysis tab (web UI)

The **Reports & Analysis** tab extends the Executive View: **At a glance** (live KPIs from **`dashboard.php`**, plus a friendly **compliance** line for the latest finished job), **Snapshot drift** (narrative + risk badge + callouts from **`compare_summary`**, with high/critical context when both scans appear in the same **`trends_summary`** window), **Scan history** (SVG trend charts and tables from **`trends_summary`** only), then a visually secondary **Analysis & tools** block (baseline, manual compare, full compliance, artifacts, admin debug). Snapshot sections use completed jobs only, not live inventory.

| Area | What it does | Typical API |
|------|----------------|---------------|
| **At a glance** | **Live / current:** assets, open findings, high+critical via **`dashboard.php`**. **Compliance (snapshot):** latest completed job from a tiny recent-scan list + **`compliance`** `vs_baseline=1` (job id spelled out). If the dashboard call fails, snapshot sections still load. | `dashboard.php`, `trends_summary`, `compliance` |
| **Snapshot drift** | Auto **snapshot diff** to latest: **effective baseline** when valid and ≠ latest; else first **prior** completed job ≠ latest (scans among recent list). Plain-language summary; bounded **`compare_summary`**. | `trends_summary`, `compare_summary` |
| **Scan history (snapshots)** | Last **N** completed jobs (**≤ 50**): per-job asset and open-finding counts; bounded **SVG line charts** (assets, open findings, high+critical) plus tables. Loads on tab open; **Reload history** refetches. | `trends_summary` |
| **Analysis & tools** | Baseline status/save, **manual** reference vs current compare (full cards), **compliance detail**, **artifacts** / **`artifact_summary`**, admin **`compare_debug`** / **`baseline_debug`**. | `baseline`, `set_baseline`, `compare_summary`, `compliance`, `artifacts`, `artifact_summary`, debug actions |

**Why slim endpoints:** `compare` and `action=artifact` can return large JSON. The Reports & Analysis tab loads **`dashboard.php`**, **`trends_summary`**, **`compare_summary`**, **`compliance`**, and **`baseline`** in small bounded steps (no automatic full **`compare`** or raw **`payload_json`**). Admins may use **`compare_debug`**, **`baseline_debug`**, and **`artifact_payload_preview`** for truncated or sampled debug views.

### Baseline: config vs effective

- **`baseline_config_job_id`** — value stored in `config` under **`phase13_baseline_job_id`** (what an operator set).
- **`baseline_job_id` (effective)** — id actually used for diffs: same job only if it **exists**, **`status=done`**, not trashed, and has **at least one** `scan_asset_snapshots` row. Otherwise **`null`** and **`baseline_unavailable`** is true when a config id was set but could not be resolved.

### Scan scopes and reporting filters

SurveyTrace can tag each **`scan_jobs`** row with an optional **`scope_id`** (see **`scan_scopes`** and **`scan_scope_baselines`**). Reporting behavior:

- **Named scope** — Each network/environment row in **`scan_scopes`** can have **one** baseline in **`scan_scope_baselines`** (`scope_id` → `baseline_job_id`). **Set baseline** in the UI with a named scope selected writes that row (not the legacy global key). Drift and compliance for that filter use the scoped baseline first, then the previous completed job in the same scope.
- **Unscoped only** — Jobs with **`scope_id` NULL or 0** mean **scope unknown**, not one shared environment. The **legacy global** baseline (`config.phase13_baseline_job_id`) is still honored when it resolves to an unscoped job. Automatic snapshot drift **without** a baseline only pairs the latest unscoped job to a **prior** unscoped job when **`st_reporting_unscoped_jobs_compatible`** is true (same **`schedule_id` > 0**, or same **`batch_id` > 0**, or same non-empty **`target_cidr`**, or same normalized label prefix before a separator, or same **`collector_id` > 0` together with one of those signals). Otherwise drift is not auto-shown; charts and manual compare still work.
- **All scopes (overview)** — Lists **all** completed jobs for trends and selectors. There is **no** single baseline that applies to every network. **Snapshot drift** for the globally latest scan uses that scan’s **named** scope baseline when applicable, else the **legacy global** baseline when the latest job is unscoped, else the most recent **prior job in the same named scope**. When the latest job is **unscoped**, a prior reference is chosen only if the compatibility rule above matches—unrelated legacy scans (e.g. different products) are **not** auto-compared by date alone. **Manual compare** can still pick any two jobs; cross-scope pairs and **both-unscoped incompatible** pairs get **low-confidence** wording via **`scope_alignment`** and **`diff_summary.unscoped_pair_uncertain`** on **`compare_summary`**.

Cross-scope manual compare remains allowed but uses cautious wording when **`scope_alignment.comparable`** is false. When both jobs are unscoped and compatibility cannot be verified, **`diff_summary.unscoped_pair_uncertain`** is true.

### External reporting event model (canonical contract)

Canonical event payloads and producer mapping live in **`api/lib_reporting_event_model.php`** (PHP helpers + file docblock). Any HTTPS delivery must emit payloads that match this contract unchanged. Row-based push targets live in **`integrations`** (see **`api/lib_integrations.php`**) with shared HTTPS helpers in **`api/lib_integrations_outbound.php`** (reserved **`integration_webhook_*`** settings are not wired to automatic emits today).

**Event producers (map into canonical shape; outbound webhook on artifact insert when configured):**

| Producer | API / table | Canonical mapping |
|----------|-------------|---------------------|
| Change detection | **`GET /api/change_alerts.php`** | `st_reporting_event_from_change_alert_row()` — `data_plane`: **live** (alerts are not snapshot rows). |
| Compliance evaluation | **`GET /api/reporting.php?action=compliance`** | `st_reporting_event_from_compliance_summary()` — **snapshot** job findings. |
| Report artifact creation | **`report_artifacts`** (insert from **`reporting_cli.php`** materialize; list via **`GET …?action=artifacts`**) | `st_reporting_event_from_report_artifact_row()` — **snapshot**; outbound delivery is **manual** (Integrations test/sample) or optional legacy Settings webhook — **no automatic fan-out** today. |
| Findings lifecycle | **`findings.php`**, lifecycle columns on **`findings`** | Same canonical `subject.finding_id` + `payload` pattern; map at integration boundary from existing API shapes (no new endpoint here). |

**Canonical event skeleton** (see `st_reporting_event_canonical_skeleton()`): `schema_version`, `event_id`, `source`, `occurred_at`, `event_type`, `severity`, `scope` (`scope_id`, `scope_name`), `subject` (`job_id`, `finding_id`, `asset_id`), `data_plane` (`snapshot` \| `live`), `payload` (opaque structured body).

**Reporting endpoints safe for external consumers** (session-auth, bounded payloads; prefer over `compare` / full **`artifact`**):

| Action | Notes |
|--------|--------|
| **`trends_summary`** | Per completed job: counts, **`scope_id`**, **`scope_name`**, drift compatibility fields. Response includes **`scope_context`** (request filter echo). |
| **`compare_summary`** | Counts + **`finding_events`** + **`scope_alignment`** (includes **`job_a_scope_name`**, **`job_b_scope_name`**) + **`unscoped_pair_uncertain`**. **`scope_context`** on envelope. |
| **`compliance`** | Rule pass/fail for one job; includes job **`scope_id`**, **`scope_name`**, and **`scope_context`**. |

**`scope_context`** object: `scope_filter` (null = all scopes, `0` = unscoped-only filter, `N` = named scope), `scope_id` / `scope_name` (mirror of filter for named scopes; null when “all”), `scope_kind` (`all` \| `unscoped` \| `named`).

**Snapshot vs live:** Reporting **`trends_summary`**, **`compare_summary`**, and **`compliance`** operate on **frozen per-job snapshot tables** and completed **`scan_jobs`**. **`dashboard.php`** and **`change_alerts`** reflect **live** or **operational** state — downstream systems must not treat them interchangeably without labeling `data_plane`.

### Integrations (push and pull)

**Goal:** one place to store **push** destinations and **pull / API** consumers. **Pull authentication is always per-integration:** create one **`integrations`** row per external consumer (Grafana, Prometheus, Splunk scripted input, etc.), generate a token on that row, and rotate or disable it independently — without wiring broad automatic exports yet.

#### Storage and admin API

- **Migrations:** `migration_phase14_1_integrations_v1` creates **`integrations`**. `migration_phase14_1_integrations_per_pull_token_v1` adds **`token_hash`**, **`token_created_at`**, **`token_last_used_at`**, **`token_last_used_ip`** (bcrypt hash only; never plaintext). **`migration_phase16_remove_legacy_integrations_pull_token_v1`** removes any unused **`config.integrations_pull_token_bcrypt`** row from older installs. Fresh **`sql/schema.sql`** includes the same integration columns.
- **Types (internal):** `splunk_hec`, `syslog`, `webhook`, `loki`, `prometheus_pull`, `json_events_pull`, `report_summary_pull`, `grafana_infinity_pull`. The UI maps these to friendly labels. The **`*_pull`** types are **pull/API rows** only: each **enabled** row whose bearer verifies for a route may access only the endpoints mapped to that type (see table below). Push types never accept pull bearer auth on those URLs.
- **Admin HTTP:** **`GET /api/integrations.php`** — list rows plus **`per_integration_pull_token_configured`** (whether any **enabled** pull row has a bcrypt **`token_hash`** for the pull types). Never returns **`token_hash`** or raw secrets. **`POST /api/integrations.php`** (CSRF, admin): `action` = `create` \| `update` \| `delete` \| `test` \| `sample` \| **`rotate_token`** (body: **`integration_id`**, pull types only) \| **`debug_pull_token`** (see below). List rows include **`type_label`**, **`mode`** (`push` \| `pull`), **`destination_summary`** (push destination or pull API paths), and for pull types only **`token_configured`**, **`token_created_at`**, **`token_last_used_at`**, **`token_last_used_ip`**. **`auth_secret_clear`** on update clears stored push secrets. Changing **`type`** away from a pull type clears that row’s pull token fields. Saving a pull type clears **`endpoint_url`**, **`host`**, **`port`**, and **`auth_secret`** on the server.
- **`debug_pull_token` (admin diagnostics):** Body: **`integration_id`**, optional **`route`** (default **`dashboard`**), optional **`view`** in **`metrics`**\|**`trends`**\|**`events`**\|**`compliance`** (forces **`route=dashboard`** for dashboard URL checks), optional **`token`**, optional **`metrics_format`** / **`events_format`**. Response includes **`allowed_types`**, **`debug_failure_reason`**, **`token_hash_prefix`**, **`token_created_at`**, **`token_last_used_at`**, **`schema_ready`** — **never** the plaintext token or full hash. **This `POST` is not authenticated with the pull token:** you must call it as an **admin** (browser **session cookie** after login, or **HTTP Basic** when **`auth_mode`** is **`basic`**). A bare `curl` without cookies/Basic gets **`401`** with `Authentication required` — that is **not** SurveyTrace rejecting the `st_int_…` value. **`POST`** also requires header **`X-CSRF-Token`** (same value as the logged-in session’s CSRF token) and a same-origin **`Origin`** or **`Referer`**; easiest is **DevTools → Network → copy as cURL** from any successful Integrations **`POST`** after signing in.

#### Per-integration pull tokens

- **Recommended:** one **`integrations`** row per external consumer (e.g. one **`grafana_infinity_pull`** for Grafana Infinity + starter dashboard, one **`report_summary_pull`** if you only need dashboard/report summary without other Grafana JSON routes, one **`json_events_pull`** for Splunk scripted input). Use **Generate / Rotate token** on that row; rotating one consumer does not change another’s hash.
- **Per-row storage:** **`password_hash`** in **`integrations.token_hash`**. **`POST … rotate_token`** with **`integration_id`** returns **`token`** once; afterward only **`token_configured`** and timestamps appear in lists.
- **Auth header / query:** **`Authorization: Bearer <token>`** or **`?token=`** (Bearer is preferred for logs). If **both** are present, **Bearer wins** (avoids a stale or placeholder `?token=` from overriding a correct datasource header). Only **enabled** integrations whose **type** matches the route are candidates; wrong type, disabled row, or bad token → **401** JSON (`invalid token for this endpoint` / `token required`). If **no** enabled pull row for that route has a usable token hash, the route returns **503** JSON (`no enabled pull integration token configured for this endpoint`). Deleted rows remove the hash with the row.

#### Pull endpoints vs integration types (Grafana / API clients)

**Tokens are endpoint-specific.** A **`report_summary_pull`** token **will not** work on **`GET /api/integrations_events.php`**. A **`json_events_pull`** token **will not** work on **`GET /api/integrations_dashboard.php`** (or **`integrations_report_summary.php`**). A **`grafana_infinity_pull`** token works on the Grafana-oriented URLs listed below (still **not** on Prometheus **text** metrics). Use the integration **type** that matches the URL you call; rotate tokens per row under **Integrations**.

| Endpoint | Use case | Required integration type(s) | Token source | Notes |
|----------|-----------|-------------------------------|--------------|--------|
| **`GET /api/integrations_dashboard.php`** | Full bundle **or** raw slices **`?view=trends`**, **`events`**, **`metrics`**, **`compliance`** | **`report_summary_pull`** or **`grafana_infinity_pull`** | Bearer or `?token=` | Raw **`view=`** responses are JSON only (no `{ "ok": true, … }` envelope). Full bundle unchanged without **`view`**. |
| **`GET /api/integrations_report_summary.php`** | Slim summary JSON | **`report_summary_pull`** or **`grafana_infinity_pull`** | Bearer or `?token=` | |
| **`GET /api/integrations_events.php`** | Events **`format=json`** or **`jsonl`** | **`json_events_pull`**; **`grafana_infinity_pull`** allowed for **`format=json`** only | Bearer or `?token=` | **`jsonl`** → **`json_events_pull`** only. |
| **`GET /api/integrations_metrics.php`** | Prometheus text (default) or **`?format=json`** | **`prometheus_pull`**; **`grafana_infinity_pull`** allowed for **`format=json`** only | Bearer or `?token=` | Prometheus **text** scrape → **`prometheus_pull`** only. |

**Grafana starter:** prefer **`grafana_infinity_pull`** + datasource **`Authorization`** (see **`integrations/starter/grafana/README.md`**). **`report_summary_pull`** remains valid for dashboard/report summary only.

#### Choosing a type (quick reference)

| You are integrating… | Choose (UI label) | Internal `type` |
|------------------------|-------------------|-----------------|
| Grafana Infinity (starter dashboard; optional JSON metrics/events) | **Grafana Infinity dashboard pull** | **`grafana_infinity_pull`** |
| Grafana Infinity / JSON panels (dashboard + report summary only) | **Grafana Infinity / report summary pull** | **`report_summary_pull`** |
| Prometheus scrape, Grafana / Alloy metrics | **Prometheus / Grafana metrics pull** | **`prometheus_pull`** |
| Splunk HEC receiver | **Splunk HEC push** | **`splunk_hec`** |
| Splunk scripted or modular input polling JSONL | **Splunk scripted input / JSON events pull** | **`json_events_pull`** |

#### Push (manual only)

- **`api/lib_integrations.php`** — `st_integrations_push_send_test()` posts canonical **`surveytrace.reporting.event.v1`** JSON for **`webhook`** (optional HMAC `X-SurveyTrace-Signature: sha256=…` when `auth_secret` is set), **`splunk_hec`** (wrapped HEC envelope; `Authorization: Splunk <hec_token>`), **`loki`** (Grafana Loki push JSON; optional Bearer), **`syslog`** (RFC5424 single line over UDP by default; set `extra_json` to `{"syslog_transport":"tcp"}` for TCP). Short curl timeouts (≈4s connect / 10s total).
- **UI:** **Integrations** sidebar (admin): **Push** and **Pull / API** sections, type-aware add/edit, per-row **Generate / Rotate token** on pull rows, **Test** / **Sample** on push rows only.

#### Pull (token required)

| Integration `type` | Allowed pull routes |
|--------------------|---------------------|
| **`prometheus_pull`** | **`GET /api/integrations_metrics.php`** (including default Prometheus text) |
| **`json_events_pull`** | **`GET /api/integrations_events.php`** (including **`format=jsonl`**) |
| **`report_summary_pull`** | **`GET /api/integrations_report_summary.php`**, **`GET /api/integrations_dashboard.php`** |
| **`grafana_infinity_pull`** | **`GET /api/integrations_dashboard.php`**, **`GET /api/integrations_report_summary.php`**, **`GET /api/integrations_events.php?format=json`**, **`GET /api/integrations_metrics.php?format=json`** |

| Endpoint | Notes |
|----------|--------|
| **`GET /api/integrations_metrics.php`** | Default: **Prometheus** text (**`prometheus_pull`** only). **`?format=json`**: **`prometheus_pull`** or **`grafana_infinity_pull`**. |
| **`GET /api/integrations_dashboard.php`** | Full bundle: **`report_summary_pull`** or **`grafana_infinity_pull`**. Optional **`?view=trends|events|metrics|compliance`** returns **raw JSON** slice (no **`pull_client`** on that path). |
| **`GET /api/integrations_events.php?since=…&limit=…&format=json\|jsonl`** | **`format=jsonl`**: **`json_events_pull`** only. **`format=json`**: **`json_events_pull`** or **`grafana_infinity_pull`**. |
| **`GET /api/integrations_report_summary.php?scope_id=…`** | **`report_summary_pull`** or **`grafana_infinity_pull`**. Includes **`pull_client`**. |

Successful per-integration auth updates **`token_last_used_at`** / **`token_last_used_ip`** best-effort (failure does not fail the request).

#### Example `curl` (replace host and tokens)

```bash
# Grafana / Infinity — dashboard bundle (report_summary_pull or grafana_infinity_pull token)
curl -fsS -H 'Authorization: Bearer st_int_YOUR_PULL_TOKEN' \
  'https://surveytrace.example.com/api/integrations_dashboard.php?event_limit=50'

# Raw trends slice for Infinity (?view=trends)
curl -fsS -H 'Authorization: Bearer st_int_YOUR_PULL_TOKEN' \
  'https://surveytrace.example.com/api/integrations_dashboard.php?view=trends&trend_limit=20'

# Splunk / scripts — JSON events (json_events_pull token)
curl -fsS -H 'Authorization: Bearer st_int_YOUR_JSON_EVENTS_PULL_TOKEN' \
  'https://surveytrace.example.com/api/integrations_events.php?since=2026-05-01T00:00:00Z&limit=100&format=json'

# Prometheus — text metrics (prometheus_pull token)
curl -fsS -H 'Authorization: Bearer st_int_YOUR_PROMETHEUS_PULL_TOKEN' \
  'https://surveytrace.example.com/api/integrations_metrics.php'
```

#### Starter visualization packages (Splunk + Grafana Infinity)

Shipped under **`integrations/starter/`** (also copied to **`/opt/surveytrace/integrations-starter/`** on master **`deploy.sh`**):

| Path | Purpose |
|------|---------|
| **`integrations/starter/splunk_surveytrace/`** | Splunk app: **`app.conf`**, **`macros.conf`**, **`props.conf`** (**`surveytrace:reporting:event`**), **`default/inputs.conf`** + **`bin/surveytrace_events.py`** for optional JSONL pull, starter **saved searches** and Simple XML **dashboards**. See **`README.md`** in that folder. |
| **`integrations/starter/grafana/`** | **`surveytrace-infinity-starter.json`** + **`README.md`**. Panels use **`GET /api/integrations_dashboard.php?view=…`**; **Bearer only on the Infinity datasource** (secure fields — **no tokens in JSON**). Starter uses **panel-level datasource only** so per-query targets do not override auth. If panels return **401**, use **Query Inspector** (see Grafana **`README.md`**) before changing SurveyTrace. **No Prometheus required** for the starter. |

Canonical HEC / JSON lines should remain **`surveytrace.reporting.event.v1`** (see **`api/lib_reporting_event_model.php`**). Dashboard-friendly scope fields: top-level **`scope_id`** / **`scope_name`** on envelopes and (for JSON events, default) on each event via **`st_reporting_event_envelope_scope_fields()`**.

#### Grafana Cloud / Splunk patterns (standards-based)

- **Metrics:** Prometheus scrape of **`integrations_metrics.php`** (Bearer), or Grafana Alloy → Prometheus remote_write.
- **Logs / events:** Loki push integration row targeting `…/loki/api/v1/push`, or poll **`integrations_events.php`** (`format=jsonl`) on a timer.
- **Splunk:** HEC push row, or scripted input polling **`integrations_events.php`**.
- **Security:** never log raw pull tokens or HEC secrets; **`st_integrations_redact_string()`** sanitizes integration logs. Failed outbound tests update **`last_error`** only on the integration row — they do not block scans, reporting, or the scheduler.

#### Legacy Settings webhook (unchanged)

- **`integration_webhook_*`** keys on **`POST /api/settings.php`** persist legacy URL/HMAC settings, but the server **does not call** **`st_integrations_outbound_emit()`** from any scheduler or reporting path (materialize hook removed; **no automatic fan-out**). Use **Integrations** push targets with **Test** / **Sample** for outbound checks; a future release may reattach the settings webhook to selected events.

#### Sample Prometheus excerpt

```
# HELP surveytrace_assets_total Assets in live inventory table.
# TYPE surveytrace_assets_total gauge
surveytrace_assets_total 42
# HELP surveytrace_open_findings_total Open findings (resolved=0).
# TYPE surveytrace_open_findings_total gauge
surveytrace_open_findings_total 7
surveytrace_open_findings_by_severity{severity="high"} 3
# HELP surveytrace_last_scan_timestamp Unix time of latest finished scan (UTC).
# TYPE surveytrace_last_scan_timestamp gauge
surveytrace_last_scan_timestamp 1746134400
surveytrace_scope_assets_total{scope_id="1"} 120
surveytrace_scope_open_findings_total{scope_id="1"} 4
```

#### Sample JSONL event line (canonical)

```
{"schema_version":"surveytrace.reporting.event.v1","event_id":"change_alert:901","source":"change_alerts","occurred_at":"2026-05-01T12:00:01Z","event_type":"change.new_finding","severity":null,"scope":{"scope_id":null,"scope_name":null},"subject":{"job_id":55,"finding_id":102,"asset_id":12},"data_plane":"live","payload":{"detail":{},"asset_ip":"10.0.0.5","dismissed_at":null}}
```

#### Sample report summary (trimmed)

```json
{
  "ok": true,
  "schema_version": "surveytrace.integrations.report_summary_envelope.v1",
  "scope_id": 1,
  "scope_name": "HQ",
  "scope_context": {"scope_filter": 1, "scope_id": 1, "scope_name": "HQ", "scope_kind": "named"},
  "latest_completed_scan": {"job_id": 88, "finished_at": "2026-05-01 10:15:00", "label": "nightly", "scope_id": 1, "scope_name": "HQ"},
  "posture": {"job_id": 88, "asset_snapshots": 120, "open_findings_total": 4, "open_findings_by_severity": {"critical": 0, "high": 1}},
  "posture_flat": {"job_id": 88, "scope_id": 1, "scope_name": "HQ", "snapshot_asset_count": 120, "open_findings_total": 4, "critical_open": 0, "high_open": 1, "medium_open": 0, "low_open": 0},
  "compliance_summary": {"overall_pass": true, "rules": [{"id": "no_critical_open", "pass": true, "detail": "No open critical findings in snapshot."}]},
  "drift": {"available": true, "baseline_job_id": 70, "counts": {}, "finding_events": []}
}
```

#### Bulk-assigning legacy `scope_id` (operators)

SQLite examples (run with a backup; adjust ids):

```sql
-- By schedule: tag all jobs from one recurring schedule into scope 2
UPDATE scan_jobs SET scope_id = 2 WHERE schedule_id = 42 AND (scope_id IS NULL OR scope_id = 0);

-- By target string: tag jobs that share a CIDR literal
UPDATE scan_jobs SET scope_id = 3 WHERE target_cidr = '10.0.0.0/16' AND (scope_id IS NULL OR scope_id = 0);

-- Hand-picked job ids
UPDATE scan_jobs SET scope_id = 4 WHERE id IN (101, 102, 103);
```

### Soft limits

- **`compare`**, **`compare_summary`**, and **`compare_debug`** use the same per-job size guard: when either job’s `COUNT(asset snapshots)+COUNT(finding snapshots)` exceeds **200,000**, the API returns HTTP **400** with a clear message. **`compare_summary`** returns only **`counts`**, **`finding_events`**, **`warnings`**, and job metadata (smaller JSON for UI).
- **`compare_debug`** returns at most **`sample_limit`** rows per bucket (default **15**, max **50**); **admin** role only.
- **`trends`** — `limit` default **30**, max **200** completed jobs per response.
- **`trends_summary`** — `limit` default **30**, max **50**; each point is counts only (no per-host/CVE rows). Uses the same batched aggregate queries as **`trends`**.
- **`artifacts`** — list `limit` default **20**, max **100** rows (metadata columns only).

### Endpoints (session auth + CSRF on POST)

| Action | Method | Roles | Notes |
|--------|--------|-------|-------|
| `compare` | GET | viewer+ | `job_a`, `job_b` required, must differ (full diff rows) |
| `compare_summary` | GET | viewer+ | Same as `compare`; **`diff_summary`** (counts + events + **`scope_alignment`** incl. scope names + **`unscoped_pair_uncertain`**) + **`scope_context`** |
| `summary` | GET | viewer+ | `job_id`; optional `vs_baseline=1` |
| `trends` | GET | viewer+ | `limit` default 30, max 200 (legacy shape: `finished_at`, `assets`) |
| `trends_summary` | GET | viewer+ | `limit` default 30, **max 50** — each point: `job_id`, **`scope_id`**, **`scope_name`**, `timestamp` (legacy SQLite-style), **`timestamp_iso`** (UTC ISO-8601 `…Z` for Grafana), counts, `label`, drift fields; envelope **`scope_context`** |
| `compliance` | GET | viewer+ | `job_id`; optional `vs_baseline=1`; job **`scope_id`** / **`scope_name`** + **`scope_context`** |
| `baseline` | GET | viewer+ | Current baseline config + effective id |
| `baseline_debug` | GET | **admin** | Validation detail for baseline |
| `compare_debug` | GET | **admin** | `job_a`, `job_b`, optional `sample_limit` |
| `artifacts` / `artifact` | GET | viewer+ (list) / scan_editor+ (**`artifact`**) | **`artifacts`** lists saved scheduled-report rows (metadata only). **`artifact`** returns full **`payload_json`** (use sparingly); scan_editor+ |
| `artifact_summary` | GET | scan_editor+ | `id` — metadata + **`summary`**, **`delta`**, **`compliance_summary`**, **`diff_summary`** only (no diff row arrays) |
| `artifact_payload_preview` | GET | **admin** | `id` — pretty-printed stored JSON, **truncated** (~14k chars) for debugging |
| `set_baseline` | POST | scan_editor+ | JSON `{"job_id":N}` + CSRF |

**Artifact summary:** `artifact_summary` **reads and decodes** `payload_json` **only on the server** to support legacy rows; the JSON **response is always slim** (metadata, `summary`, `delta`, `compliance_summary`, `diff_summary`, optional `payload_warning` — no full diff row arrays). The Reports & Analysis UI does **not** call `action=artifact` or ship full stored payloads by default.

### Example: `GET /api/reporting.php?action=compare&job_a=12&job_b=20`

```json
{
  "ok": true,
  "diff": {
    "job_a": 12,
    "job_b": 20,
    "semantics": "A=reference/baseline, B=current",
    "warnings": [],
    "assets_new_in_b": [],
    "assets_missing_in_b": [],
    "findings_new_in_b": [],
    "findings_only_in_a": [],
    "finding_resolution_changes": [],
    "finding_events": {
      "marked_resolved_in_b": 0,
      "reopened_in_b": 0,
      "open_in_a_absent_in_b_snapshots": 0
    },
    "counts": {
      "assets_a": 42,
      "assets_b": 43,
      "assets_only_in_a": 1,
      "assets_only_in_b": 2,
      "findings_only_in_a": 0,
      "findings_only_in_b": 3,
      "marked_resolved_in_b": 0,
      "reopened_in_b": 0,
      "open_in_a_absent_in_b": 0
    }
  }
}
```

Row arrays use legacy names (`assets_new_in_b` = hosts only in B; `assets_missing_in_b` = only in A; `findings_only_in_a` = CVE rows in A’s snapshot missing from B’s). **`counts`** adds stable **`assets_only_in_*` / `findings_only_in_*`** mirrors for UI.

### Example: `GET /api/reporting.php?action=baseline`

```json
{
  "ok": true,
  "baseline_config_job_id": 12,
  "baseline_job_id": 12,
  "baseline_unavailable": false
}
```

### Example: `GET /api/reporting.php?action=baseline_debug` (admin)

```json
{
  "ok": true,
  "baseline": {
    "baseline_config_job_id": 12,
    "baseline_job_id": null,
    "validation_ok": false,
    "reason_code": "job_not_done",
    "reason_detail": "Baseline job must have status done."
  }
}
```

### Scheduled report artifacts (`report_artifacts`)

Stored JSON uses **`schema_version`: 1** and a **slim** shape: `job_id`, `schedule_id`, `schedule_name`, `baseline_*`, `generated_at`, **`summary`**, **`delta`**, **`compliance_summary`**, **`diff_summary`** (counts + `finding_events` only — not full CVE/host lists). Full diffs remain available via **`compare`** / **`summary`** over HTTP.

### CLI: `php reporting_cli.php materialize <schedule_id>`

On success, prints one JSON line to stdout, for example:

```json
{"ok":true,"schedule_id":3,"artifact_id":14,"duration_ms":87}
```

### Observability

PHP **`error_log`** receives lines prefixed with **`SurveyTrace.reporting`** and a JSON object including **`_event`** (e.g. `reporting.compare`, `reporting.baseline_resolve`, `reporting.materialize_start` / `materialize_end`, `reporting.report_payload`, `reporting.baseline_set`) and **`_ts_ms`**. Use for debugging without exposing debug payloads to non-admin users.

### Reporting validation checklist

Use after deploy once migration **`migration_phase13_reporting_v1`** has run and you have at least one **`done`** job that has snapshot rows. Snapshot semantics: counts and diffs are from **`scan_asset_snapshots`** / **`scan_finding_snapshots`** only, not live inventory tables.

1. **Baseline** — Open **Reports & Analysis** → baseline card loads without waiting on job pickers; config and effective ids match expectations. **Viewer:** can read baseline; **Set baseline** hidden. **Scan editor / admin:** set baseline via UI or **`POST …?action=set_baseline`** (CSRF).
2. **Compare summary** — Two distinct completed jobs → **`compare_summary`** response includes **`diff_summary`** only (counts, **`finding_events`**, warnings); verify DevTools response has **no** full `assets_new_in_b` / `findings_new_in_b` arrays at the top level.
3. **Artifact list / detail** — **Scan editor / admin:** with a **`report`** schedule that has produced rows, **Artifacts** lists entries (**`artifacts`**, capped list). **Details** uses **`artifact_summary`** only (slim body); UI must not call **`action=artifact`** for that flow. **Viewer:** artifacts section hidden.
4. **Compliance summary** — Pick a job → **Load compliance** with and without **vs baseline**; pass/fail and rule lines when applicable; readable empty/error states.
5. **Trends** — **Load trends** (10–50 jobs); **`trends_summary`** payload is a bounded array of points (`job_id`, `timestamp`, counts, severity buckets); tables + optional SVG sparklines; empty state when no qualifying **done** jobs.
6. **Scheduled report artifact** — **`schedule_action=report`**; after scheduler run, new **`report_artifacts`** row with materialized **`payload_json`** (verify via **`artifacts`** or admin **`artifact_payload_preview`**).
7. **Admin debug endpoints** — As **admin**: **`baseline_debug`**, **`compare_debug`** (`sample_limit` ≤ 50), **`artifact_payload_preview`** (truncated ~14k chars). **Viewer / scan editor** must not receive admin-only payloads from these actions.
8. **RBAC quick pass** — **Viewer:** Reports & Analysis shows **At a glance**, **Snapshot drift**, **Scan history**, and read-only **Analysis & tools** (no baseline save, no artifacts list, no admin debug). **Scan editor:** artifacts + set baseline; no admin debug unless also admin.
9. **Panel isolation** — If **`scan_history`** fails (e.g. network), baseline and (for scan_editor+) artifacts panels should still populate after refresh; job pickers show the error option until history loads again.

## SQLite locking and concurrency

SurveyTrace uses **SQLite** for `data/surveytrace.db` (inventory, findings, auth, config) with a **separate** `data/nvd.db` for the NVD corpus so CVE sync heavy writes do not contend with the main app database.

**Reality:** SQLite allows **one writer at a time** even in WAL mode. Readers usually proceed; writers queue. “Database is locked” means a writer held the transaction longer than your peer’s **busy_timeout** wait.

**What the product already does**

- **WAL** (`PRAGMA journal_mode=WAL`) and **`synchronous=NORMAL`** on PHP and Python connections. WAL creates **`surveytrace.db-wal`** and **`surveytrace.db-shm`** next to the main file — the **`data/`** directory must stay **writable** by both **`surveytrace`** and **`www-data`** (group), with **setgid** on the directory so new sidecars inherit the right group (`setup.sh` / `deploy.sh` enforce this).
- **Long busy waits** (default **60s**) so API workers wait for the scanner/ingest instead of failing immediately — see **`api/db.php`** (`st_sqlite_runtime_pragmas`) and **`daemon/sqlite_pragmas.py`** (shared across scanner, scheduler, collector ingest, sync scripts).
- **Shorter write transactions** in the scanner and ingest worker: batched commits (e.g. every 100 rows) for snapshots, findings, and change-detection so the writer lock is not held for an entire scan.
- **Bootstrap serialization**: `.surveytrace_bootstrap.lock` during first-time migrations so many PHP workers do not replay `ALTER TABLE` in parallel after a deploy.
- **Session / PDO release** on long PHP paths (`session_write_close`, `st_db_release_connection()` around operator AI) so one browser tab does not pin the session **file** lock; DB connection can be dropped during external I/O so SQLite is not held open across slow network calls.

**Optional tuning (environment)**

| Variable | Effect |
|----------|--------|
| `SURVEYTRACE_SQLITE_BUSY_TIMEOUT_MS` | PHP and Python: milliseconds SQLite waits for the writer (default **60000**, clamped **1000–600000** in PHP; Python uses same idea via `sqlite_pragmas.py`). |
| `SURVEYTRACE_SQLITE_MMAP_BYTES` | **PHP** (`api/db.php`) and **Python** (`sqlite_pragmas.py`): `PRAGMA mmap_size` in bytes (default **67108864**). Set to **`0`** to disable mmap (e.g. some **NFS** or unusual kernels). |

**Operations that reduce pain**

- Keep **`surveytrace.db` on local disk** (not a network filesystem) if possible.
- After deploys that touch **`api/db.php`** migrations, **restart Apache or php-fpm** once so each worker runs bootstrap once (see [Updating / Deploying Changes](#updating--deploying-changes)).
- Size **PHP-FPM** `pm.max_children` (or Apache worker count) conservatively: each child holds a DB handle; very large pools increase overlap and lock retries.
- Optional maintenance when idle: `sqlite3 /opt/surveytrace/data/surveytrace.db 'PRAGMA wal_checkpoint(TRUNCATE);'`

**When to consider migrating off SQLite**

- You need **sustained concurrent writes** from many services, **multi-master**, or **row-level locking** semantics — then **PostgreSQL** (or another client/server RDBMS) is the usual upgrade path. That is a **large** architectural change (schema migration, connection pooling, backup/restore story). For typical single-master SurveyTrace installs, the combination above is the intended first line of defense.

## Quick Start

```bash
git clone https://github.com/veddegre/surveytrace.git
cd surveytrace
sudo bash setup.sh   # choose (1) full server or (2) collector when prompted
```

On a **full server**, the web UI will be available at `http://your-server-ip/` after setup. Collectors have no local UI; configure `/etc/surveytrace/collector.json` and the service per **`collector/README.md`**.

See **[Setup and deploy (master vs collector)](#setup-and-deploy-master-vs-collector)** for non-interactive setup, `deploy.sh` behavior, and legacy marker files.

## Manual Installation

```bash
# System dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-venv php php-sqlite3 php-curl php-fpm \
    apache2 libapache2-mod-proxy-fcgi nmap sqlite3 qrencode samba-common-bin

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
# After pulling changes from git (same on master and collector nodes)
cd ~/surveytrace-repo
git pull
bash deploy.sh
```

`deploy.sh` decides whether this host is a **master** or **collector** install (see **[Setup and deploy (master vs collector)](#setup-and-deploy-master-vs-collector)**) and syncs the appropriate files. You can still run `bash collector/deploy.sh` directly on a collector; root `deploy.sh` is the recommended single entry point.

On a **master**, `deploy.sh` copies the tracked application files from the repo into `/opt/surveytrace` (not a blind `cp -r` of the whole tree). It includes, among others:

- **`api/`** — all HTTP endpoints used by the UI, including `feeds.php`, **`feed_sync_lib.php`** (shared by `feeds.php` and `daemon/feed_sync_worker.php`), `scan_history.php`, **`devices.php`** (device list/detail + merge), **`ai_actions.php`** (self-contained on-demand operator AI: CVE triage, explain host, refresh scan summary), `settings.php`, etc.
- **`daemon/`** — scanner, scheduler, fingerprint engine, enrichment `sources/`, **`asset_lifecycle.py`**, **`feed_sync_worker.php`** + **`feed_sync_cancel.py`** (UI cancel / cooperative stop), and the `sync_*.py` feed scripts
- **`public/`** — `index.php` and `css/app.css`
- **`sql/schema.sql`** — reference copy for new installs (existing DBs are migrated by the app on startup)

It then restarts `surveytrace-daemon`, `surveytrace-scheduler`, and **`surveytrace-collector-ingest`** (master-side worker that drains `collector_ingest_queue` and applies collector payloads into `surveytrace.db`). `deploy.sh` installs **`surveytrace-collector-ingest.service`** under `/etc/systemd/system/` and enables it; without this service, uploads still land under `data/collector_ingest/` but scans stay **running** until something processes the queue.

Verify on the master:

```bash
sudo systemctl status surveytrace-collector-ingest --no-pager
sudo journalctl -u surveytrace-collector-ingest -n 40 --no-pager
```

**If logs show `sqlite3.OperationalError: unable to open database file`:** the worker resolves the DB via `SURVEYTRACE_INSTALL_DIR` (set in **`surveytrace-collector-ingest.service`**) and `data/surveytrace.db`, same as PHP’s `api/db.php`. Ensure **`/opt/surveytrace/data`** is directory **readable and writable** by user **`surveytrace`** (WAL needs write on the directory), and that **`surveytrace.db`** is owned **`surveytrace:www-data`** with mode **660** as applied by **`setup.sh` / `deploy.sh`**. After fixing permissions, restart: `sudo systemctl restart surveytrace-collector-ingest`.

**Executive AI summary (run-wide):** after all collector chunks are applied and master CVE/per-asset enrichment finishes, the worker **queues** run-wide Ollama/cloud summary work in SQLite table **`collector_ingest_exec_ai_queue`** and processes it on a **separate daemon thread** so slow or timing-out models **do not block** chunk ingest or mark ingest failed. `summary_json` gains **`master_executive_ai_followup`**: `queued` → `done` (or `abandoned_*` after max retries). Optional wall clock cap: **`SURVEYTRACE_EXEC_AI_WALL_SECONDS`** (default **120**, clamped 20–900).

To **re-queue** a stuck chunk after the DB is healthy (example job **44**), mark the corresponding `collector_ingest_queue` row **`pending`** again (only if the JSON file still exists under `data/collector_ingest/`):

```bash
sqlite3 /opt/surveytrace/data/surveytrace.db "UPDATE collector_ingest_queue SET status='pending', error_msg=NULL, next_attempt_at=NULL WHERE job_id=44 AND status='failed';"
sudo systemctl restart surveytrace-collector-ingest
```

## Collector Deployment (Multi-System)

Collectors are packaged under `collector/` and are intended for remote network sites.

- Full collector install/onboarding guide: **`collector/README.md`**
- Repo root **`setup.sh`** — option **2** runs collector setup (same as below)
- `collector/setup.sh` — installs a parity collector runtime and systemd service (`surveytrace-collector`) with passive capture capability defaults (`CAP_NET_RAW`, `CAP_NET_ADMIN`)
- **`deploy.sh`** (repo root) — on a collector host, automatically runs the collector sync path after `git pull`
- `collector/deploy.sh` — updates runtime files on an existing collector node (also invoked by root `deploy.sh`)
- `collector/hardening.sh` — applies baseline host hardening

Collector node requirements (remote site host):

- Debian 12+ or Ubuntu 22.04+
- 2 vCPU minimum (4 vCPU recommended)
- 2 GB RAM minimum (4 GB recommended)
- 8 GB free disk minimum (20 GB recommended)
- Outbound HTTPS (`443/tcp`) to master; no inbound collector ports required
- Root/sudo for setup and passive discovery capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`)

Quick sizing guide (per collector):

| Approx active hosts in site scope | Recommended collector size | Suggested `max_jobs` |
|---|---|---|
| Up to 250 | 2 vCPU / 2 GB RAM | 1 |
| 250-1000 | 4 vCPU / 4 GB RAM | 1-2 |
| 1000-3000 | 8 vCPU / 8 GB RAM | 2-3 |
| 3000+ | 8+ vCPU / 16+ GB RAM (or split by subnet/site) | 2-4 |

Start conservative and increase `max_jobs` gradually after confirming acceptable scan duration and network load.

Collector-to-master flow:

1. Collector registers using the install token created in **Settings → Collector setup** (`collector_install_token` on the server) and receives a bearer token.
2. Collector polls for assigned jobs.
3. Collector runs local parity phases and submits chunked payloads.
4. **`surveytrace-collector-ingest`** on the master applies queued chunks from `data/collector_ingest/` into the DB and runs centralized CVE + AI enrichment.

Scheduling and guardrails:

- Collectors use the same `scan_schedules` pipeline as master runs (`collector_id` selects execution site).
- Schedule targeting is managed in Scan/Schedules UI (collector overview is operational status/control only).
- Optional per-collector CIDR allowlists prevent out-of-scope runs; enforcement is applied on queue/save and at runtime dispatch.

This keeps collectors useful on isolated networks without requiring internet egress from collector nodes.

If **AI operator** buttons fail, redeploy **`api/ai_actions.php`** (single file; see `deploy.sh`) and load any SurveyTrace page once so SQLite migrations add **`ai_findings_guidance_cache`** / **`ai_host_explain_cache`** to `assets`.

When libcurl returns an empty body, the API falls back to **`proc_open()` + `curl`** (system `curl`, not PHP’s extension). Confirm it is allowed for the FPM user (often `www-data`): `sudo -u www-data php -r 'var_export(function_exists("proc_open")); echo PHP_EOL;'` should print `true`. If `php.ini` / pool config lists **`proc_open`** in **`disable_functions`**, remove it (or the fallback cannot run). Align **`request_terminate_timeout`** / **`max_execution_time`** / **`TimeOut`** (Apache proxy) with long Ollama calls: operator AI uses **`ai_operator_ollama_timeout_s`** in config (default **900** seconds, clamped 120–3600; **Settings → AI enrichment → Operator AI wait**). The API raises `set_time_limit` for those requests, but the web server must not kill the worker first. If errors still show **180** seconds, the server is likely running an old **`api/ai_actions.php`** / **`api/db.php`** build without `st_ai_operator_ollama_timeout_cap()`.

**`database is locked` / `lsof` shows many `apache2` lines:** See **[SQLite locking and concurrency](#sqlite-locking-and-concurrency)**. In short: many workers holding the file open is normal; restart **Apache/php-fpm** after deploys and tune busy timeout / pool size as above.

**After upgrading `api/db.php` with new SQLite migrations:** restart **Apache or php-fpm** once so every PHP worker re-runs the one-time bootstrap (migrations are skipped on later reconnects inside the same worker for speed).

**Feed sync from the browser:** Under **PHP-FPM** (default for nginx and for Apache when installed with `setup.sh`, which uses `mod_proxy_fcgi` to the FPM socket), sync runs in the same request after `fastcgi_finish_request()`. Under **Apache `mod_php`** (unusual if you followed `setup.sh`), the API spawns `php daemon/feed_sync_worker.php …` in the background, which requires `exec()` not to be in `disable_functions`, and requires `feed_sync_worker.php` to be present on disk (deploy copies it). NVD runs with **`--recent`** from PHP so the job matches weekly cron behavior and stays within typical HTTP worker limits.

SQLite schema changes apply automatically on next API or daemon startup (`ALTER TABLE` migrations); fresh installs use `sql/schema.sql` with a complete `scan_jobs` definition.

## Changelog

**Canonical app version** is the single line in **`VERSION`** at the install root (same directory as **`api/`** and **`daemon/`**). **`api/st_version.php`** reads **`VERSION`** into the PHP constant **`ST_VERSION`** (also loaded at the top of **`public/index.php`** so the UI works before the DB exists). Python daemons and sync scripts read the same file via **`daemon/surveytrace_version.py`**. When you cut a release: edit **`VERSION`**, then keep **`RELEASE_NOTES.md`** and the changelog entries below in sync for humans and auditors.

`0.2.0` is the first GitHub release baseline. Earlier work was internal pre-release iteration.
Published release summaries are also tracked in `RELEASE_NOTES.md`.

### Unreleased

- (no entries yet)

### 0.16.0

- **Roadmap note** — **`VERSION` 0.16.0** is a **Phase 15 (Integrations)** follow-up (UI + legacy config cleanup), not the same as **Roadmap Phase 16** in [Upcoming](#upcoming) (monitoring / ops). **`migration_phase16_remove_legacy_integrations_pull_token_v1`** is a SQLite migration **name** for ordering after the Phase 14.1 integration migrations; it does **not** mean roadmap Phase 16 is delivered.
- **Integrations UX** — Admin **Integrations** tab: **Push** vs **Pull / API** sections, friendly type labels, type-aware add/edit (modal), quick-start guidance (Grafana Infinity, Prometheus/Alloy, Splunk HEC, Splunk scripted input), per-row token reveal messaging.
- **Pull auth** — Removed unused **legacy global** pull token (`config.integrations_pull_token_bcrypt`); pull endpoints accept **only** per-integration bearer tokens of the correct enabled type (**401** / **503** semantics unchanged intent). Migration **`migration_phase16_remove_legacy_integrations_pull_token_v1`** deletes the old config key if present.
- **API** — **`GET /api/integrations.php`** drops legacy global status fields; list rows add **`type_label`**, **`mode`**, **`destination_summary`**. **`POST rotate_pull_token`** removed.
- **Splunk starter** — **`integrations/starter/splunk_surveytrace/`**: **`bin/surveytrace_events.py`**, **`default/inputs.conf`**, **`default/surveytrace_pull.ini.example`**, nav + overview dashboard XML; README for **`local/surveytrace_pull.ini`** and checkpointing.
- **Fallbacks** — **`api/st_version.php`** and **`daemon/surveytrace_version.py`** default to **`0.16.0`** when **`VERSION`** is missing.

### 0.15.0

- **Version alignment** — **`VERSION` 0.15.0** was the SemVer line where **Phase 14** (scan scopes) and the **first Phase 15** (integrations) ship landed together. README **Changelog** and **`RELEASE_NOTES.md`** stay aligned per release; **0.16.0** above is the next Integrations-focused patch (still **Phase 15** roadmap scope — see that entry’s roadmap note).
- **Scan scopes & reporting filters (Phase 14)** — **`scan_scopes`**, **`scan_jobs.scope_id`**, **`scan_scope_baselines`**; **`api/scan_scopes.php`**; **`lib_scan_scopes.php`**; reporting and **Reports & Analysis** support **named** / **unscoped** / **all** filters, **`scope_context`**, cross-scope compare cautions (**`st_reporting_unscoped_jobs_compatible`**). Migration **`migration_phase14_scan_scopes_v1`**.
- **Integrations push + pull (Phase 15)** — **`integrations`** table; **`api/integrations.php`**, **`lib_integrations.php`**, **`lib_integrations_dashboard.php`**, **`lib_integrations_outbound.php`**; manual push **test/sample**; read-only pull APIs (**`integrations_metrics.php`**, **`integrations_events.php`**, **`integrations_report_summary.php`**, **`integrations_dashboard.php`**); **per-integration** pull tokens (**`migration_phase14_1_integrations_v1`**, **`migration_phase14_1_integrations_per_pull_token_v1`**); starter **`integrations/starter/`** (Splunk + Grafana); admin **Integrations** UI; **`deploy.sh`** ships integration PHP and copies starters to **`/opt/surveytrace/integrations-starter/`**.
- **Documentation** — README roadmap (completed **14–15**, upcoming **16–22**); descriptive section titles outside the roadmap; starter readmes cross-linked to **Integrations (push and pull)**.
- **Fallbacks** — **`api/st_version.php`** and **`daemon/surveytrace_version.py`** use **`0.15.0`** when **`VERSION`** is missing or unreadable.

### 0.14.3

- **Per-integration pull tokens** — Route-specific bearer verification; **`pull_client`** on JSON pull responses; usage timestamps; UI per-row rotate. See **`RELEASE_NOTES.md`**.

### 0.14.2

- **Integrations hardening** — **`integrations_metrics.php`** rejects invalid **`format=`**; packaging/docs validation for pull APIs and legacy webhook behavior. See **`RELEASE_NOTES.md`**.

### 0.14.1

- **Integrations foundation** — First ship of **`integrations`**, global pull token, push helpers, four pull endpoints, Integrations UI, starter packages, scope fields on integration event envelopes where applicable. See **`RELEASE_NOTES.md`**.

### 0.13.0

- **Reporting foundation** — **`api/lib_reporting.php`**, **`api/reporting.php`**, **`api/reporting_cli.php`**; migration **`migration_phase13_reporting_v1`**; **`report_artifacts`**; schedule action **`report`**; baseline config **`phase13_baseline_job_id`**.
- **API surfaces** — **`compare_summary`**, **`artifact_summary`**, admin **`artifact_payload_preview`**; existing **`compare`**, **`summary`**, **`trends`**, **`compliance`**, **`artifacts`**, **`set_baseline`**.
- **Reports & Analysis UI** — Sidebar tab: baseline status, snapshot drift narrative, bounded compare summary, lightweight **`trends_summary`** charts, artifact list, artifact detail (slim summary), compliance panel (bounded rule output).
- **SQLite / ops** — Reporting CLI retries on lock; shared busy timeout / WAL behavior documented in **SQLite locking and concurrency**; scheduler subprocess isolation for PHP report work.
- **Version** — **`VERSION`** **0.13.0**; **`api/st_version.php`** / **`daemon/surveytrace_version.py`** fallbacks aligned.

### 0.12.0

- **Asset lifecycle** — Coverage-based **`active` / `stale` / `retired`** on **`assets`** (migration **`migration_phase12_asset_lifecycle_v1`**); **`daemon/asset_lifecycle.py`** + scanner/collector evaluation; **`change_alerts`** types **`asset_stale`**, **`asset_retired`**, **`asset_reactivated`**.
- **Operator fields** — **`owner`**, **`business_unit`**, **`criticality`**, **`environment`** on **`assets`** (API + UI); **`identity_confidence`**, **`identity_confidence_reason`** on schema.
- **Export + API** — **`export.php`** extended CSV/JSON columns; **`assets.php`** **`lifecycle_status`** filter.
- **Setup / deploy** — **`setup.sh`** WAL/SHM ownership guard; **`deploy.sh`** ships **`asset_lifecycle.py`**, normalizes WAL sidecars, optional PHP **`st_db()`** bootstrap as **www-data** before daemon restart; **`collector/deploy.sh`** includes **`asset_lifecycle.py`**.
- **Version** — **`VERSION`** **0.12.0**; **`api/st_version.php`** / **`daemon/surveytrace_version.py`** fallbacks aligned.

### 0.11.0

- **Explainable CVE triage** — SQLite migration `migration_phase10_finding_triage_v1`: **`findings`** columns for lifecycle-adjacent triage (**`confidence`**, **`risk_score`**, **`detection_method`**, **`provenance_source`**, **`evidence_json`**); **`daemon/finding_triage.py`** + scanner/collector wiring; **`GET /api/findings.php`** sort/filter on triage fields; **Vulnerabilities** + host panel + CSV/JSON export.
- **CVE intelligence** — migration `migration_phase11_cve_intel_v1`: **`cve_intel`** (KEV metadata, EPSS, OSV ecosystems JSON); **`daemon/sync_cve_intel.py`** (CISA KEV JSON, EPSS file/API, OSV per-CVE); **`api/feed_sync_lib.php`** / **`feeds.php`** target **`cve_intel`**; dashboard + Settings status; **`findings`** / export expose **`intel`**.
- **Fingerprint / WebFP** — stronger **VMware** and **Proxmox** classification (titles, banners, vCenter VAMI **5480**, Wappalyzer-derived rules mapped to **`hv`** where the tech name implies a hypervisor); see **`daemon/fingerprint.py`**, **`daemon/scanner_daemon.py`**, **`daemon/sync_webfp.py`**.
- **SQLite locking** — shared **`daemon/sqlite_pragmas.py`** + **`api/db.php`** `st_sqlite_runtime_pragmas()` (**60s** busy wait, optional **mmap**, **`temp_store=MEMORY`**); README section **SQLite locking and concurrency** documents ops and **`SURVEYTRACE_SQLITE_*`** env vars.
- **Version tracking** — root **`VERSION`** file + **`api/st_version.php`** / **`daemon/surveytrace_version.py`**; **`deploy.sh`** copies **`VERSION`** to **`/opt/surveytrace/`**.
- **Deploy** — **`deploy.sh`** ships **`sync_cve_intel.py`**, **`sqlite_pragmas.py`**, and **`surveytrace_version.py`**; restart **web PHP** after **`api/db.php`** so migrations **10** and **11** run.

### 0.9.0

- **Change detection** — SQLite **`change_alerts`** table and **`findings`** lifecycle fields (migration `migration_phase9_change_detection_v1`); **`daemon/change_detection.py`** drives alerts and CVE state transitions from **`scanner_daemon.py`** and **`collector_ingest_worker.py`**; **`GET/POST /api/change_alerts.php`**; findings API adds **`accept_risk`** and lifecycle-aware **resolve** / **unresolve** / **`GET ?lifecycle=`**; **Change alerts** sidebar tab with dismiss controls (scan editors+). **Deploy:** copy **`change_detection.py`** and **`change_alerts.php`**; restart **Apache/php-fpm** once so migrations run.

### 0.8.2

- **Scan profiles** — phase validation allows **Full TCP** to run banner/fingerprint phases despite an empty fixed `port_list` (all-TCP `-p-` mode on LAN in the scanner). *(0.8.2 also shipped a separate **Fast Full TCP** UI profile; that option has been **removed** because it often returned empty port lists. Any legacy `fast_full_tcp` value in the API or database **normalizes to `full_tcp`**.)*
- **Scanner** — continues to **union prior open ports** (and related banner/CPE hints) on upsert for full-port profiles so inventory does not regress on a thin result pass.
- **Collectors** — redeploy **`daemon/profiles.py`** and **`daemon/scanner_daemon.py`** on collector hosts after upgrade (`collector/deploy.sh` copies both).

### 0.8.1

- **Collector install token** — Settings is generate-only (confirm + one-time reveal with copy); `POST /api/settings.php` no longer accepts a raw `collector_install_token` field.
- **Collector overview** — list API exposes `online_recent_2m` so aggregate “online (<=2m)” counts match per-row freshness; “Set ranges” uses a modal instead of a browser prompt.
- **Fingerprinting** — Linux SSH/distro evidence prevents an open RDP port alone from classifying the host as a Windows workstation (better for Linux VMs with xrdp or similar).

### 0.8.0

- **Collector architecture (MVP + parity runner)** — added collector registration/auth (`collector_checkin.php`, `collector_jobs.php`, `collector_submit.php`), management API (`collectors.php`), ingest worker (`collector_ingest_worker.py`), and remote collector packaging under `collector/`.
- **Centralized enrichment + isolated collectors** — collectors run local parity discovery and upload chunked artifacts; master performs CVE/AI enrichment asynchronously.
- **Unified scheduling model** — collectors use the same `scan_schedules` engine as master scans (`collector_id`), including cron, pause/resume, and missed-run policies.
- **UX and role coverage** — scan/schedule forms support collector targeting, scan queue/history/detail show source, Settings adds install token management, collector overview adds status/assignment/token controls; scan editors can target collectors while collector mutations remain admin-only.
- **Safety guardrails** — per-collector allowed CIDR ranges are enforced at queue/save, run-now, schedule assignment, scheduler enqueue, and collector dispatch.

### 0.7.0

- **Minor release (operator AI)** — bumps the minor version because this release adds a new on-demand AI surface (not just a patch).
- **Scan AI summary reliability** — daemon uses a longer Ollama timeout for run-wide summaries, always records `ai_scan_summary_status` / `ai_scan_summary_detail` when AI is enabled, and scan/dashboard/history paths decode `summary_json` more robustly (including UTF-8 substitution). UI shows structured summary or status detail so completed runs are not blank.
- **On-demand operator AI** — `POST /api/ai_actions.php` (`findings_guidance`, `explain_host`, `refresh_scan_summary`; Ollama helpers inlined in that file). Host detail panel adds AI operator hints with cached results on **`assets.ai_findings_guidance_cache`** / **`assets.ai_host_explain_cache`** (migrated on startup). Scan history detail adds **Refresh AI summary** for `done` jobs.
- **Deploy** — `deploy.sh` copies `ai_actions.php` and post-deploy checks verify it.

### 0.6.2

- **Host rescan modal parity** — Assets host rescan now exposes the same scan controls as manual/scheduled workflows: profile defaults, phases, rates, discovery mode, exclusions, and per-run enrichment selection.
- **Deep Scan vs Full TCP clarity + behavior** — UI/help text and profile descriptions now explicitly distinguish Deep Scan (fixed expanded list) from Full TCP (`-p-` all ports on LAN). `full_tcp` now uses longer host-timeout tiers on small scopes to reduce empty-result runs.
- **Full TCP overwrite guard** — daemon upsert path now preserves prior inventory signal by unioning `open_ports` (and merging banners / fallback CPE data) when a weak `-p-` pass returns fewer results.
- **Scheduled + on-demand DB backups** — scheduler-managed DB backups with Settings controls (enable, cron, retention days, keep-count), backup status telemetry, plus an admin **Run backup now** action and restore helper script.

### 0.6.1

- **Scan delete hardening** — trash lifecycle (**move to trash**, **restore**, **admin-only permanent delete**) with retention-based automatic purge.
- **Trash retention controls** — configurable retention (`scan_trash_retention_days`) is exposed in **Settings** and enforced by scheduler-side purge logic.
- **Scan history trash views + RBAC** — Scan History now supports **Active/Trash/All** semantics with role enforcement: viewers are active-only, scan editors/admins can manage trash actions, and admin is required for permanent purge and retention changes.
- **Audit attribution for trash lifecycle** — added audit events for `scan.job_trashed`, `scan.job_restored`, `scan.job_purged`, and `scan.trash_retention_updated`.

### 0.6.0

- **Identity/auth hardening** — OIDC-only SSO path, RBAC coverage pass, OIDC JWKS signature validation, and role-aware UI gating.
- **Profile + account recovery UX** — My Profile self-service, modal-based admin temporary password flows, forced first-login password change, and improved MFA setup/recovery handling.

### 0.5.0

- **Device identity** — **`devices`** table and **`assets.device_id`** (FK); idempotent migration (`migration_device_identity_v1` in `config`) in **`api/db.php`** and **`daemon/scanner_daemon.py`**; 1:1 backfill for legacy rows.
- **Scanner** assigns / preserves `device_id` on asset upsert; optional fill of **`devices.primary_mac_norm`** when a MAC is learned.
- **API:** `GET/POST /api/devices.php` (list, detail, **merge**), `GET /api/assets.php?device_id=`, `GET /api/export.php?device_id=`, dashboard includes `device_id` in top-vulnerable query.
- **UI:** Devices tab, device detail side panel (with merge), Assets integration (filter, sort, single search + numeric device id + Enter, clear filters); **`deploy.sh`** copies **`api/devices.php`** (required for the Devices tab).
- **Docs:** **`docs/DEVICE_IDENTITY.md`** — device vs address model and API notes.
- **Scan history search** — `GET /api/scan_history.php` accepts optional **`q`** (max 120 chars) to filter list rows by **`scan_jobs.label`**, **`target_cidr`**, or **`id`**. **Scan history** page search (debounced) uses **`limit=200`** when **`q`** is set; queue panel still reflects unfiltered **`GET /api/scan_status.php`** history. Run detail assets include **`device_id`** for navigation to **Devices** / **Assets**.

### 0.4.0

- **NVD API key** — optional key in **Settings** (stored in SQLite, not echoed on read) or `NVD_API_KEY` in the environment (env wins). Improves NVD feed sync rate limits for `sync_nvd.py`, cron, and in-app sync.
- **Per-scan enrichment** — `POST /api/scan_start.php` accepts optional `enrichment_source_ids` (omit = all enabled, `[]` = skip external enrichment for that run, `[id,…]` = subset). Stored on `scan_jobs` and honored by `scanner_daemon.py`.
- **Scanner** — external enrichment no longer holds a SQLite write transaction during slow calls (avoids UI/API stalls during UniFi or SNMP timeouts).
- **Schedules** — `scan_schedules` gains `enrichment_source_ids`; schedule UI and `POST /api/schedules.php` align with manual scan options (phases, `rate_pps` / `inter_delay`, priority, enrichment subset, profile confirmation for high-impact profiles). Scheduler enqueues jobs with the same fields.
- **Schema** — `sql/schema.sql` `scan_jobs` expanded to match migrated production columns; `dashboard.php` / `schedules.php` migrations cover any straggler columns on first request.

### 0.3.0

- **Queue and execution improvements** — support for multiple queued jobs, sequential execution by priority/age, queued cancel and running abort actions, and retry workflow improvements.
- **Scheduling foundations** — cron-based schedule model, scheduler daemon service, schedule CRUD/run controls, and timezone-aware next-run handling in UI/API.
- **Discovery expansion** — routed-friendly host discovery modes (`auto` / `routed` / `force`), broader hostname/service discovery, and early enrichment/fingerprinting quality improvements.

### 0.2.0

- **Safer defaults and scan profiles** — profile-driven scanning introduced with guarded defaults for different environments.
- **Profile-aware scanning pipeline** — per-profile phase/rate/delay/port behavior enforced by daemon and stored on scan jobs.
- **High-impact confirmation gates** — confirmation prompts added for higher-risk scan behaviors before execution.

## NVD Database Setup

### NVD API key (recommended)

NIST offers a free API key for the public CVE API; it raises rate limits so `sync_nvd.py` completes much faster than the anonymous tier.

1. Request a key: [NVD API key request](https://nvd.nist.gov/developers/request-an-api-key) (NIST account required).
2. **In the web UI:** open **Settings**, find the NVD section, paste the key, and click **Save**. After save, the UI only shows a masked placeholder until you **Remove** the key; you must remove it before pasting a different one (the API rejects overwrite while a key exists). The key is stored server-side in SQLite (`config.nvd_api_key` in `data/surveytrace.db`). It is **never returned** on `GET /api/settings.php` — the API only exposes `nvd_api_key_configured` (true/false).
3. **Via environment:** set `NVD_API_KEY` in the environment of the process that runs `sync_nvd.py` (systemd unit, cron, or shell). If `NVD_API_KEY` is set, it **overrides** the key saved in the database (useful when you do not want the key in SQLite, or when cron runs without reading the same DB path).

`daemon/sync_nvd.py` resolves the key in this order: **`NVD_API_KEY` env → Settings (database)**. Cron jobs run as `surveytrace` typically see only the DB key unless you export `NVD_API_KEY` in the crontab or wrapper script.

**`setup.sh`** asks for an optional key (hidden input) before the first-sync prompt and stores it in `config` the same way as the web UI.

### Initial sync and cron

```bash
# Initial full sync: large transfer + SQLite build (~1+ GB on disk).
# With NVD_API_KEY: often tens of minutes; without a key: commonly multi-hour.
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
- **Cancel** touches `data/feed_sync_cancel` for long-running sync scripts (NVD, CVE intel, full **Sync all**); Python exits after the current fetch step — expect **several minutes** for a typical incremental NVD run (longer without an API key or when NIST has a large update batch)

### Feed sync install paths (optional)

If PHP cannot find `daemon/sync_*.py` (unusual directory layout), set **`SURVEYTRACE_ROOT`** to the SurveyTrace install root (the directory that contains `daemon/` and `api/`). When the web stack is not PHP-FPM and the worker is spawned with a CLI `php` binary, **`SURVEYTRACE_PHP_CLI`** can point to an explicit PHP binary (see `api/feed_sync_lib.php`).

## Authentication (web UI)

Password hashing and mode live in the `config` table (`auth_hash`, `auth_mode`). With no password configured, the UI is open (typical first-run).

- **`session`** (default): local login via `POST /api/auth.php?login=1`; the UI uses a session cookie after login.
- **`oidc`**: SSO login via `api/auth_oidc.php` (with JWT signature validation against provider JWKS), with optional breakglass local login.

Set `auth_mode` in **Access control** (or directly in `config`). Supported UI modes are `session` and `oidc`; legacy `basic` remains backend-compatible, and `auth_mode=saml` from older installs is treated as `oidc`. Session idle timeout is configurable under **Settings** (`session_timeout_minutes`).

### Local account lifecycle (session mode)

- **Admin-managed temporary passwords** — when admins create a local user or set a new password for a user, it is treated as a temporary password.
- **Forced first-login password change** — users with temporary passwords must set a new password before continuing.
- **My profile self-service** — users manage display name/email and (for local accounts) password + MFA in **My profile**.
- **MFA** — local accounts support TOTP + one-time recovery codes; OIDC-authenticated accounts treat password/MFA as IdP-managed.
- **MFA QR generation** — QR images are generated locally via `api/auth_qr.php` + `qrencode`; MFA secrets are not sent to external QR services.

## Architecture

```
Browser → Apache/PHP-FPM → PHP API → data/surveytrace.db (app state: users, assets, findings, scans, schedules, config)
                                           ↕
                      scanner_daemon.py    ← processes queued jobs
                      scheduler_daemon.py  ← enqueues jobs on schedule + retention tasks

Feed/CVE data path:
  daemon/sync_nvd.py   → data/nvd.db            (local CVE corpus used for correlation)
  daemon/sync_oui.py   → data/oui.txt           (MAC vendor cache)
  daemon/sync_webfp.py → data/webfp_signatures.json (web fingerprint signatures)

Collector ingest path (when collectors are enabled):
  collector_agent.py → api/collector_submit.php → data/collector_ingest/ + collector queue tables (then async apply into surveytrace.db)
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
| Deep Scan | Aggressive nmap `-sV` + SNMP on SurveyTrace’s **expanded fixed port list** (~60+ ports, not `1–65535`); requires confirmation | ❌ | ❌ |
| Full TCP | **All** TCP ports (`-p-`) with `-sV`; longest per-host runtime; requires confirmation. **Routed** mode still uses a per-host **`-p-`** sweep (with extra CIDR-based discovery seeding when ping scans miss hosts); expect long runtimes or sparse results over VPNs — prefer **Standard Inventory** or **Deep Scan** for routed reconnaissance | ❌ | ❌ |
| OT Careful | Passive-first OT baseline; very low scan rates; requires confirmation | ✅ | ✅ |

**Full TCP and existing inventory:** the scanner unions new results with any **open ports already stored** for that IP so a timed-out or filtered pass does not clear a good prior inventory row (`prior_inventory_ports_merged` may appear in discovery metadata).

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

**Roadmap phase numbers** (Phase 1, Phase 2, … below) are a **planning index**. They are **not** the same as **`VERSION`** / SemVer: e.g. **`VERSION` 0.16.0** can ship while **Phase 16** in [Upcoming](#upcoming) is still future work.

**`migration_phaseN_*`** keys in **`api/db.php`** use integers for **ordering and grouping**; they often align with roadmap phases (e.g. **`migration_phase14_scan_scopes_v1`**) but not always — **`migration_phase16_remove_legacy_integrations_pull_token_v1`** is still **Integrations (Phase 15 scope)** cleanup, not “Roadmap Phase 16 — monitoring.”

Shipped work is summarized in **`RELEASE_NOTES.md`** and in [Changelog](#changelog) above.

### Completed (summary)
- **Phase 1 — Safer defaults + scan profiles** — profile-driven scanning shipped with profile selection in UI, per-profile daemon guardrails (rate/delay/phase/ports), profile persistence on jobs, and high-impact confirmation prompts.
- **Phase 2 — Job queue improvements** — multi-job queueing (with priority order), cancel/abort actions, retry support, failure visibility, and queue/history separation in the UI.
- **Phase 3 — Scheduling core** — `scan_schedules` + scheduler daemon, schedule CRUD/run-now/toggle APIs, schedule UI, timezone-aware cron evaluation, pause/resume controls, and configurable missed-run handling.
- **Phase 4 — Discovery improvements** — routed-friendly host discovery (`auto`/`routed`/`force`), subnet-aware behavior, broad hostname/service enrichment (including mDNS and HTTP title fingerprints), and startup OUI backfill improvements.
- **Phase 5 — Device identity** — Logical **`devices`** linked from **`assets`**; scanner + migrations; Devices UI; **`POST /api/devices.php`** merge (logged to **`scan_log`**). Details: **`docs/DEVICE_IDENTITY.md`**. *Not built:* un-merge, split/reassign assets, findings-by-device filter, `device_identifiers` table (optional follow-ons).
- **Phase 6 — Identity & access** — OIDC-first auth, local accounts + role management, MFA/recovery flows, profile self-service, endpoint RBAC coverage, and expanded account/audit logging.
- **Phase 7 — Scan delete hardening** — soft delete/trash lifecycle for scan runs, restore flow, admin-only permanent purge, retention-based purge, and audit coverage.
- **Phase 8 — Collector architecture (MVP + parity runner)** — remote collector registration + bearer auth, collector control APIs/UI, unified schedule targeting (`collector_id`), scan source visibility, per-collector rate limits, centralized ingest + enrichment worker, and CIDR allowlist guardrails for safe remote execution.
- **Phase 9 — Change detection** — `change_alerts` feed (new asset, port change, new CVE, finding mitigated/reopened); **`findings`** lifecycle columns (`new` → `active`, scanner-driven `mitigated` when absent from correlated results, `accepted` via API, `reopened` after regression); **`GET/POST /api/change_alerts.php`** and **Change alerts** UI; scanner + collector ingest share **`daemon/change_detection.py`**.
- **Phase 10 — Explainable CVE triage** — per-finding **confidence**, **risk score**, **detection method**, **provenance**, and **evidence** JSON; scanner + **`daemon/finding_triage.py`** + collector parity; **Vulnerabilities** / host UI, **`findings.php`** filters/sorts, **`findings_export.php`**.
- **Phase 11 — CVE intelligence** — **`cve_intel`** sidecar (CISA **KEV**, **FIRST EPSS**, **OSV** ecosystems); **`daemon/sync_cve_intel.py`** + feed sync wiring; **`intel`** on finding payloads and exports (complements NVD for mixed fleets: Linux, Windows, **macOS**, **Hyper-V**, containers, and **iOS / iPadOS / Android**-relevant shared components where data exists).
- **Phase 12 — Asset lifecycle** — coverage-based **`active` / `stale` / `retired`** vs scan scope (**`target_cidr`** + **`scan_asset_snapshots`**); **`daemon/asset_lifecycle.py`**; **`change_alerts`** (**`asset_stale`**, **`asset_retired`**, **`asset_reactivated`**); operator fields (**`owner`**, **`business_unit`**, **`criticality`**, **`environment`**, **`identity_confidence`**, **`identity_confidence_reason`**); **`export.php`** / **`assets.php`**. See **[Asset lifecycle](#asset-lifecycle)**.
- **Phase 13 — Baselines & reporting** — snapshot **`compare`** / **`compare_summary`**, **`summary`**, **`trends`**, **`compliance`**; global baseline (**`phase13_baseline_job_id`**, **`scan_jobs.is_baseline`**); **`report_artifacts`** and **`schedule_action`** **`report`** (**`reporting_cli.php`**); **Reports & Analysis** UI (report-style snapshot drift, **`trends_summary`** line charts, baseline, manual compare, artifacts + slim detail, compliance). See **[Reporting API](#reporting-api)**. *Follow-ons:* CSV export, richer compliance rules.
- **Phase 14 — Scan scopes & reporting filters** — **`scan_jobs.scope_id`**, **`scan_scopes`**, **`scan_scope_baselines`**, cross-scope reporting; named-scope baselines; cautious auto-drift rules for unscoped job pairs (**`st_reporting_unscoped_jobs_compatible`**). Migration: **`migration_phase14_scan_scopes_v1`**.
- **Phase 15 — Integrations (push + pull)** — **`integrations`** table; admin **`/api/integrations.php`**; manual push test/sample (**webhook**, **Splunk HEC**, **Loki**, **syslog**); read-only **pull** HTTP APIs (**metrics**, **events**, **report summary**, **dashboard** bundle) with **per-integration** bearer tokens; starter Splunk/Grafana under **`integrations/starter/`**; **Integrations** UI. Migrations: **`migration_phase14_1_integrations_v1`**, **`migration_phase14_1_integrations_per_pull_token_v1`**. *Deferred:* automatic scan/change/report fan-out to integration rows.
- **SemVer 0.16.0 (still Phase 15 — Integrations)** — Admin **Integrations** UI refresh (Push vs Pull/API, type-aware forms, Splunk scripted-input starter); removal of unused legacy global pull config (**`migration_phase16_remove_legacy_integrations_pull_token_v1`**). See the **0.16.0** bullets under [Changelog](#changelog).
- **Phase 16.1 — Zabbix source connector (MVP)** — Admin **`/api/zabbix.php`** + **`api/lib_zabbix.php`** + CLI **`api/zabbix_sync_worker.php`**; tables **`zabbix_connector`**, **`zabbix_hosts`**, **`zabbix_host_interfaces`**, **`zabbix_host_groups`**, **`zabbix_host_tags`**, **`zabbix_host_problems_summary`**, **`zabbix_asset_links`**, **`zabbix_scope_map_rules`**; migration **`migration_phase16_zabbix_source_v1`**. Bounded JSON-RPC pull (hosts/interfaces/groups/tags/templates/inventory/availability + capped **`problem.get`**); asset matching by IP, DNS/hostname, visible name, MAC; read-only **`zabbix`** block on **`GET /api/assets.php?id=`** and the asset edit modal; optional **group/tag → `scan_scopes`** rules with **preview/save only** (no automatic scope writes). **Integrations** tab panel for configure/test/sync. **Not in this slice:** Zabbix as a push/alert sink, auto-overwriting operator asset fields.
- **Phase 16.2 — Zabbix operator workflow** — **`assets.scope_id`** + denorm trust columns; migration **`migration_phase16_2_zabbix_workflow_v1`**; explicit **preview → confirm → apply** scope updates (**`preview_scope_apply`**, **`apply_scope_map`** + audit **`zabbix.scope_map_applied`**); **match review** UI + manual **`link_manual`** / **`unlink_asset`** (audited); **`zabbix_asset_links.is_manual`** preserved across rematch; **`GET /api/assets.php`** Zabbix filters + optional list column. See **[Using Zabbix data in SurveyTrace](#using-zabbix-data-in-surveytrace-phase-162)**.

### Upcoming
- **Phase 16 (remainder)** — Zabbix as a SurveyTrace **output** target (health/status signals), deeper alert mapping, and related ops automation — after the **16.1** source connector baseline above.
- **Planned — TeamDynamix + Microsoft Defender enrichment** — Normalized ownership, device/user, and source-attributed vulnerability context in SurveyTrace (see **[Planned: enrichment connectors](#planned-ownership-user-context-and-vulnerability-enrichment-connectors)**). Intended to **complement** [Phase 19 — Data fusion + enrichment](#upcoming); may ship as phased slices under that umbrella or as dedicated connector releases.
- **Phase 17** — Infrastructure APIs: Proxmox / VMware / TrueNAS (and similar) as **first-class connectors** beyond passive fingerprinting.
- **Phase 18** — Source connector completion: stubbed vendors (e.g. Cisco DNA/Meraki, Juniper Mist, Infoblox, Palo Alto) behind a shared connector contract (auth, paging, retry, health, field mapping).
- **Phase 19** — Data fusion + enrichment: normalize multi-source vulnerability/advisory data (dedupe, alias mapping, conflict resolution, source weighting) and expand package/software advisory coverage.
- **Phase 20** — **UI polish:** asset timeline, bulk operations, fingerprint pattern editor. **Scan history UX:** pagination or cursor search beyond the current **200**-row cap, **date** and **status** filters, **persisted query** (URL or session) for deep links, **CSV export** of the filtered history list. **Navigation cleanup:** trim duplicate top-bar shortcuts where the sidebar already links the page. **Frontend modularization (possible):** split **`public/index.php`** into maintainable modules or bundles to reduce merge friction. **Modal consistency:** replace remaining browser-native **`alert` / `confirm` / `prompt`** flows with app-styled dialogs (including **delete integration** and other destructive or credential-related actions).
- **Phase 21** — Credentialed collection + checks engine: authenticated collection (SSH/WinRM/SNMPv3/API where appropriate), plugin/check framework, richer version/package evidence, remediation guidance metadata.
- **Phase 22** — Risk operations + governance: composite risk scoring (severity, exploitability, exposure, criticality), time-bound suppressions/exceptions, SLA tracking, stronger audit/report controls.

### Zabbix source connector — operator notes (Phase 16.1)

**Zabbix API token permissions (typical)** — Create an API token for a Zabbix user or service account that is allowed to call at least: **`apiinfo.version`** (optional), **`host.get`** (with interfaces, groups, parent templates, tags, inventory), and **`problem.get`** (recent problems; SurveyTrace aggregates counts per host, capped server-side). Deny destructive methods; SurveyTrace only reads.

**HTTP behavior** — Each JSON-RPC call uses a **short cURL timeout** (~12s connect capped). Sync pulls at most **500** hosts and **4000** problem rows per run; counts may be incomplete if the server exceeds those caps.

**Matching rules** — After each sync, SurveyTrace proposes links between Zabbix hosts and **`assets`** using, in order of intrinsic signal: **interface IP** (confidence **1.0**), **MAC** from interface or inventory (**0.97–0.98**), **technical host name** vs asset hostname (**0.95**), **interface DNS** vs asset hostname (**0.93**), **visible name** vs asset hostname (**0.88**). Pairs scoring **below 0.75** are ignored. If two signals tie on confidence, **IP beats MAC beats DNS beats hostname beats visible name**. **Greedy assignment** sorts candidate pairs by confidence and assigns each asset and each Zabbix host **at most once** so one-to-one links dominate when multiple hosts could match the same asset.

**Stored vs displayed** — **Stored** in SQLite: full connector row (token on disk), normalized **`zabbix_*`** tables plus JSON blobs on **`zabbix_hosts`** (`inventory_json`, `groups_json`, `tags_json`, `templates_json`, `interfaces_json`, `status_raw_json`) for audit/re-sync. **`zabbix_asset_links`** stores **`match_method`**, **`confidence`**, **`last_matched_at`**. The asset API and UI show a **trimmed** `zabbix` object (monitored, availability, groups, templates, tags, inventory owner/location/environment, problem count, match metadata) — not the full raw Zabbix JSON. List sizes in the API response are **capped** (e.g. groups/tags/templates) to keep payloads bounded; the UI truncates long joined strings in the asset modal.

**Scope mapping** — Rules in **`zabbix_scope_map_rules`** store **`pattern`** as a single string: for **group** rules, the Zabbix host group name; for **tag** rules, either **`TagName`** alone (match any value for that key) or **`TagName=value`** where only the **first** `=` separates key from value (empty value after `=` is allowed). Matching is case-insensitive with normalized whitespace; validation, preview, and apply all use this same format—there is no separate “catalog ID” or alternate encoding. Rules default to **disabled** until you tick **enabled** per row. **`GET /api/zabbix.php`** includes **`scope_map_catalog`**: deduplicated **group names** and **tag keys with values** from the last sync (`zabbix_host_groups` / `zabbix_host_tags`, with JSON fallbacks on host rows). The Enrichment → Zabbix UI fills **`pattern`** from those lists (or **Advanced: custom value** with the same string shape). **Run a Zabbix sync** before configuring rules so the lists are populated. **`POST`** **`preview_scope_map`** evaluates **only enabled** rules (from the posted payload) and returns suggested scope IDs for **already-linked** assets; it performs **no database writes** and SurveyTrace **never** applies scope changes from Zabbix automatically in this release.

### Using Zabbix data in SurveyTrace (Phase 16.2)

**Trust fields on assets** — After sync, each asset row can carry **`monitored_by_zabbix`**, **`zabbix_availability`**, and **`zabbix_problem_count`** (denormalized from the linked Zabbix host and problem summary). These are refreshed when links change; they are **not** a hidden write path for hostname, category, or vendor.

**Matching confidence** — Auto links store **`confidence`** and **`match_method`** on **`zabbix_asset_links`**. High scores (e.g. IP match ≈ 1.0) are strong; scores in the **0.75–0.9** band are “near threshold” and deserve review in the Integrations **Match review** panel. **`is_manual = 1`** marks operator overrides; rematch only replaces **non-manual** links.

**When to trust auto vs manual** — Prefer **auto** when several independent signals agree and confidence is high. Use **manual link** when inventory is incomplete, names collide, or you need to pin a specific Zabbix **`hostid`** to an asset; manual links are **audited** (`zabbix.link_manual` / `zabbix.unlink_asset`).

**Scope mapping workflow** — 1) **Sync Zabbix** so **`scope_map_catalog`** (groups/tags) and host links exist. 2) Save rules (each row **disabled** until you enable it), choosing patterns from the catalog or custom text. 3) **Preview mapping** (form rules) or **Build apply plan** (saved **enabled** rules only) to see **current scope → new scope**. 4) Check the explicit confirmation box and **Apply selected rows** — the server rejects stale or mismatched rows; **`zabbix.scope_map_applied`** is written to the audit log when anything is applied.

**Asset list filters** — When workflow migrations are applied, the Assets tab can filter by Zabbix monitoring, unavailable (linked but not “available”), open problems, and by **host group** or **tag** (same semantics as rules). Optional **Zbx column** shows a compact trust summary.

**Manual / CLI sync** — `php api/zabbix_sync_worker.php` from the install root (same as the Integrations **Sync now** worker). Logs append to **`data/zabbix_sync_worker.log`** when spawned via `nohup`.

### Planned: ownership, user context, and vulnerability enrichment connectors

This section is **design intent** for future work. **Zabbix (Phase 16.x)** is the first concrete **source connector** in code; TeamDynamix and Microsoft Defender should follow the same principles: **bounded sync**, **background workers**, **redacted secrets**, **explicit operator actions** for anything that changes ownership or scope, and **normalized rows** in SQLite rather than “Splunk-only” enrichment.

#### Architecture principle

| Responsibility | SurveyTrace | Splunk (or similar SIEM) |
| --- | --- | --- |
| Store normalized enrichment | Yes — durable context per asset/finding | Optional copy for search |
| Asset/finding UI and reports | Yes | No (unless rebuilt there) |
| Complex multi-source time-window correlation | No — avoid rebuilding SIEM logic | Yes |
| Alert routing / escalation | Push **events** only; not primary alert brain | Yes |
| Manual review before ownership/scope apply | Yes | N/A |

**Recommended flow:** TeamDynamix → SurveyTrace **ownership/business** enrichment → optional **Splunk** HEC/event export with the same normalized fields. Defender → SurveyTrace **device / user / CVE evidence** → Splunk correlates Defender timelines with firewall, VPN, IdP, and SurveyTrace scan events.

#### 1. TeamDynamix connector (ownership / business)

**Ingest (examples):** asset owner, responsible department, support group, ticket references, CI/asset record IDs, service/application association, business criticality, location/site — as returned by the TeamDynamix API for configured asset/CI types.

**Normalized storage (conceptual):**

- Connector config row (API base URL, auth, `last_sync_at`, `last_sync_status`, `last_error` — token never returned from API).
- **`enrichment_asset_links`** (generic) or **`teamdynamix_asset_links`**: `asset_id`, `source` = `teamdynamix`, `source_object_id`, `match_method`, `confidence`, `last_matched_at`, `is_manual`, `evidence_json`.
- **`teamdynamix_asset_context`** (or generic **`asset_enrichment_snapshots`**): `source`, `source_object_id`, `last_synced_at`, `confidence`, `payload_json` / normalized columns for owner, department, support group, tickets, CI refs, service, criticality, site.

**Rules:** Do **not** automatically overwrite **`assets.owner`**, **`business_unit`**, or other operator-edited fields when those are **locked** or marked manual. Expose **“suggested from TeamDynamix”** with confidence and timestamp; apply via **preview → confirm** (audited), mirroring Zabbix scope apply.

#### 2. Microsoft Defender (XDR + Vulnerability Management)

Treat as **three** enrichment streams merged on the same asset link:

**A. Device context** — Defender device id, name, onboarding/health, exposure level, risk level, last seen, OS/platform, software inventory (as available).

**B. User context** — Logged-in / recently observed / last observed users with timestamps and raw evidence references in `evidence_json`.

**C. Vulnerability / CVE context** — CVEs or weaknesses, affected software, remediation text, scores, remediation status, first/last seen in Defender.

**Normalized storage (conceptual):** `defender_connector`; cached device/user/vuln tables; **`defender_asset_links`** (or shared **`enrichment_asset_links`** with `source = defender`); optional **`defender_device_snapshots`**, **`defender_user_observations`**, **`defender_vulnerability_findings`** (or a unified **`external_vulnerability_evidence`** table keyed by `asset_id` + `cve_id` + `source`).

#### 3. Defender CVE handling rules (source-attributed evidence)

| Situation | Behavior |
| --- | --- |
| Defender reports CVE scanner did not | Create or enrich a **finding** (or parallel evidence row) with `provenance_source` / `detection_method` = Defender; do not delete scanner rows |
| Scanner and Defender agree | Raise **confidence**; **merge** Defender fields into `evidence_json` |
| Defender remediated, scanner still open | **Flag conflict** in UI/API; **do not** auto-resolve |
| Scanner clear, Defender still reports | Keep scanner quiet; Defender evidence **stale** or active per product semantics — surface conflict |
| Defender drops CVE, scanner still open | Scanner finding **stays active**; mark Defender slice **stale/absent** |

Deduplicate by **`asset_id` + `cve_id`** (and Defender device id where relevant). Preserve **provenance** (`scanner`, `collector`, `nvd`, `defender`, `osv`, `teamdynamix` for business-only joins, etc.) in structured JSON — aligned with existing finding triage fields where possible.

#### 4. Matching and confidence (all sources)

Match external records to SurveyTrace **assets** using: IP, hostname, FQDN, MAC, device id, serial, and **source-native IDs** (e.g. Defender device id). Store **`match_method`**, **`confidence`**, **`last_matched_at`**, **`evidence_json`**, **`is_manual`**. **Low confidence** or **conflicting** links go to a **review queue** (same pattern as Zabbix match review).

#### 5. UI expectations

- Asset detail: sections for **Ownership/business**, **Monitoring** (Zabbix), **Defender device**, **Recent users**, **External vulnerability evidence**, **Conflicts**.
- Integrations-style **review** screens: unmatched external rows, unmatched assets, low-confidence matches, owner/CVE disagreements.

#### 6. Safety (non-negotiables)

Do **not:** auto-overwrite locked/manual asset fields; auto-resolve findings from a single source; auto-change scope/ownership without confirmation; return API secrets; block scans on connector failure; require Splunk for enrichment to exist.

Do: redact secrets; cap page sizes and sync volume; background sync; connector health columns; idempotent migrations; audit log for apply/link actions.

#### 7. Planned surface area (summary)

| Area | Examples (names indicative, not final) |
| --- | --- |
| **Tables** | `teamdynamix_connector`, `teamdynamix_*`; `defender_connector`, `defender_devices`, `defender_user_observations`, `defender_vulnerabilities` or `external_finding_evidence`; shared `enrichment_asset_links` |
| **PHP** | `api/lib_teamdynamix.php`, `api/lib_defender.php`, `api/teamdynamix.php`, `api/defender.php`, workers `*_sync_worker.php` |
| **API** | Admin configure/test/sync; GET enrichment on `assets.php?id=`; POST preview/apply ownership suggestions; match review endpoints |
| **Splunk export** | Reuse or extend **HEC / push** integrations: include `asset_id`, `ip`, `enrichment.sources[]`, `defender.device_id`, `teamdynamix.ci_id`, conflict flags — **fields**, not raw SIEM searches |

#### 8. Splunk export pattern

Emit **structured events** (JSON) per sync or on change: asset identity, normalized enrichment blocks, CVE evidence summaries, conflict flags. Splunk runs **correlation searches** across Defender, Okta, VPN, firewall, and SurveyTrace **enriched** events. SurveyTrace remains the **system of record** for “what we know about this asset today”; Splunk is where **time joins** and **alerting** live.

## License

MIT License

## Author

Greg Vedders — [gregvedders.com](https://gregvedders.com)
