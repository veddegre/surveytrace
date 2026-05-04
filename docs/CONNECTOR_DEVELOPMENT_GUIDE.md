# Connector development guide

This document describes a **general pattern** for adding **read-oriented source connectors** to SurveyTrace: pull data from an external system, normalize it in SQLite, match it to assets, and expose it safely in the API and UI. **[Zabbix](../api/lib_zabbix.php)** is the **reference implementation** today; the same structure should apply to future connectors (e.g. infrastructure APIs, CMDB/XDR products) **when** those products are actually integrated — this guide does **not** imply that any specific vendor beyond Zabbix is shipped.

---

## 1. Configuration

- **Single-row or keyed config** — Most connectors use one primary config row (e.g. `zabbix_connector` with `id = 1`) plus optional child tables for rules.
- **Separate concerns** — API base URL, auth, feature toggles (enable, scheduled sync, output), and operator-tunable intervals should be distinct fields or JSON keys with clear defaults.
- **Validation on save** — Normalize URLs (trim, scheme), clamp numeric bounds (intervals, page sizes), and reject ambiguous states early in the save path.
- **Public vs secret fields** — API responses for the UI should expose **`_set` flags** (e.g. `api_token_set`) instead of returning raw secrets.

## 2. Secret handling

- **Store** API tokens or client secrets **only** server-side (SQLite); never echo them in `GET` list/detail payloads.
- **Redact** tokens in error messages and logs (`st_zabbix_redact_secrets`-style helpers per connector).
- **Rotation** — Support clearing or replacing secrets without orphaning cache rows; document whether old cache is invalidated on token change.

## 3. Test connection

- **Lightweight probe** — Prefer a cheap API call (e.g. `apiinfo.version` or equivalent) with strict timeouts.
- **Surface** success/failure in the Integrations (or equivalent) UI with **actionable** error text (HTTP status, auth failure, TLS) without leaking secrets.
- **Idempotent** — Test must not mutate production mapping tables.

## 4. Manual sync

- **Worker entrypoint** — Long-running or heavy work belongs in a **CLI worker** (e.g. `api/zabbix_sync_worker.php`) spawned from the web UI or from an operator shell, not only inside a single HTTP request.
- **Bounded work** — Cap pages, row counts, and wall time per run; resume on the next run rather than risking OOM or lock contention.
- **Progress / status** — Persist `last_sync_started_at`, `last_sync_completed_at`, `last_sync_status`, `last_error` (or equivalent) on the connector row for operators and for debugging.

## 5. Scheduled sync and freshness

- **Scheduler ownership** — A systemd user (e.g. `surveytrace`) runs **`scheduler_daemon.py`**; it must be able to **read** the worker script and **open** the SQLite DB. Use **`install_root()`**-consistent paths and correct **`api/`** permissions (see main **README** deploy/setup notes).
- **Due logic in SQL** — Compare stored timestamps to `datetime('now')` in SQLite (or a single clock source) to avoid skew between PHP and Python.
- **Locks** — Use a **row-level lock** (`scheduled_*_lock`) so overlapping manual + scheduled runs do not corrupt cache tables; clear the lock on spawn failure.
- **Freshness** — Derive operator-visible states (e.g. fresh / stale / outdated) from **cache age vs configured interval**, not from wall-clock guesses in the browser alone.

## 6. Local cache tables

- **Normalized core + JSON blobs** — Store stable columns for joins and filters; use JSON for vendor-specific payloads that may evolve.
- **Migrations** — Add tables via **`api/db.php`** migrations with versioned names; keep **`sql/schema.sql`** aligned for greenfield installs.
- **Retention** — Decide whether deletes in the upstream API propagate as hard deletes or soft tombstones in SurveyTrace; document behavior.

## 7. Matching and linking

- **Link table** — e.g. `zabbix_asset_links`: `asset_id`, foreign key to upstream id, `match_method`, `confidence`, `last_matched_at`, `is_manual`.
- **Greedy or stable assignment** — Document tie-breaking when one asset matches many external rows (Zabbix uses sorted confidence + one-to-one assignment).
- **Rematch** — Recompute non-manual links after each sync; preserve **`is_manual`** overrides.

## 8. Review queue

- **Low-confidence and conflicts** — Expose list endpoints for “needs review” pairs (below threshold, ambiguous hostname collisions).
- **Actions** — Manual link/unlink with server-side re-validation and audit entries.

## 9. Preview and apply workflow

- **Any write to operator-owned fields** (scope, hostname, ownership) should use **preview → confirm** with an explicit **`confirm: true`** (or equivalent) and row-level staleness checks.
- **Audit** — Log apply actions with enough context to reconstruct who changed what (e.g. `zabbix.scope_map_applied`).

## 10. Audit logging

- **Structured events** — Use consistent `action` names (`source.action`) for link, unlink, preview, apply, and connector save.
- **Never log secrets** — Audit payloads should reference ids and redacted snippets only.

## 11. API and UI exposure

- **Read-only enrichment on assets** — Default: enrich **`GET /api/assets.php?id=`** (and list columns where appropriate) from **cache + link tables** only; no hidden writes from a GET.
- **Dedicated connector API** — Admin configure/test/sync/status on a focused endpoint (e.g. **`/api/zabbix.php`**) with CSRF and role checks.
- **UI parity** — Integrations panel for credentials and health; Enrichment tab for operator workflows (match review, apply tools).

## 12. Export and reporting behavior

- **Push integrations** — If events are emitted (Splunk HEC, webhooks), keep payloads **structured** and **bounded**; include `asset_id`, source identifiers, and conflict flags — not raw vendor blobs unless size-capped.
- **Reporting** — Decide whether connector data appears in **live** dashboards only, **snapshot** artifacts, or both; document snapshot vs live in the main README reporting section.

## 13. Failure handling

- **Non-blocking** — Connector failure must not block scans or unrelated APIs; degrade to “not configured” / “stale” UI states.
- **Backoff** — Optional: set `next_sync_at` or status fields to avoid hammering a dead upstream.
- **Spawn failures** — Scheduler (or PHP) must clear locks and persist `last_error` so operators see a clear reason.

## 14. Security checklist

- [ ] Secrets never returned from read APIs; only “configured” flags.
- [ ] Errors and logs redacted for tokens and URLs with embedded credentials.
- [ ] HTTP client timeouts and TLS verification policy documented (no silent `verify=false` in production paths).
- [ ] SQL migrations idempotent; no dynamic SQL with unescaped user input.
- [ ] RBAC: only appropriate roles can save connector config, run sync, or apply mapping.
- [ ] Rate limits / caps on sync volume to protect SQLite and upstream APIs.
- [ ] File permissions: worker scripts readable by the **scheduler** user and PHP-FPM group as per **`setup.sh` / `deploy.sh`**.

---

## Reference: Zabbix mapping (shipped)

| Guide topic | Zabbix reference |
|-------------|------------------|
| Config + secrets | `zabbix_connector`, `st_zabbix_connector_save`, `st_zabbix_connector_public` |
| Test / sync | `POST /api/zabbix.php` actions, `api/zabbix_sync_worker.php` |
| Schedule + locks | `sync_schedule_enabled`, `next_sync_at`, `scheduled_sync_lock`, `daemon/scheduler_daemon.py` |
| Cache tables | `zabbix_hosts`, interfaces, groups, tags, problems summary |
| Links + review | `zabbix_asset_links`, match review API, `link_manual` / `unlink_asset` |
| Preview / apply | `preview_scope_map`, `apply_scope_map`, `preview_identity_apply`, `apply_identity` |
| Output (push to monitoring) | `zabbix_output_worker.php`, optional metrics — separate code path from pull |

Future connectors should reuse this **shape** (config row, worker, cache, links, preview/apply, audit) even if table and file names differ.
