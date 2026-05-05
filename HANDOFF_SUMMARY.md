# SurveyTrace handoff summary

Use this as a short context starter in a new conversation.

**Current release:** See repo-root **`VERSION`** and **`CHANGELOG.md`**. PHP exposes **`ST_VERSION`** via **`api/st_version.php`**; daemons read **`daemon/surveytrace_version.py`**.

## Product shape

- **Master** — web UI, APIs, SQLite (or Postgres where configured), scheduler, enrichment and reporting workers.
- **Collectors** — optional remote execution; **`collector/`** packaging, ingest worker on master.
- **Core flows** — scan jobs, inventory (`assets` / `findings`), optional Zabbix sync and output, reporting (job scope vs inventory scope).

## Where to look

- **`docs/wiki/README.md`** — operator documentation index
- **`api/db.php`** — schema migrations and bootstrap
- **`daemon/scanner_daemon.py`**, **`daemon/scheduler_daemon.py`**, **`daemon/collector_ingest_worker.py`**
- **`deploy.sh`**, **`setup.sh`**, **`collector/deploy.sh`**

## Suggested follow-ups for operators

1. Run CVE intelligence sync where outbound access is allowed: **`daemon/sync_cve_intel.py`**
2. After upgrades that touch web fingerprint rules, refresh: **`daemon/sync_webfp.py`**
3. Confirm backups and WAL sidecar permissions per **`docs/wiki/setup-master.md`**
