# Connector Development Guide

## Who this is for

This document is for:

- developers extending SurveyTrace
- contributors building new integrations
- operators implementing internal connectors

If you are configuring integrations through the UI, see the wiki instead.

---

## Overview

This guide defines the standard pattern for building **read-oriented connectors** in SurveyTrace.

A connector:

- pulls data from an external system
- normalizes it into local SQLite tables
- links external entities to SurveyTrace assets
- exposes enriched data through the API and UI

The Zabbix connector is the **reference implementation**:

- `api/lib_zabbix.php`
- `api/zabbix_sync_worker.php`

All connectors should follow the same structure.

---

## Design principles

All connectors must:

- be **read-first** (no destructive upstream actions)
- require **explicit operator actions** for linking or mutation
- never expose secrets
- degrade safely when upstream systems fail
- remain non-blocking to core scanning workflows

---

## 1. Configuration

- **Single-row or keyed config**  
  Most connectors use one primary config row (e.g. `zabbix_connector` with `id = 1`) plus optional rule tables.

- **Separate concerns**  
  Keep API URL, auth, feature toggles, and intervals clearly separated.

- **Validation on save**  
  - normalize URLs (scheme, trailing slash)
  - clamp numeric bounds
  - reject incomplete or ambiguous configurations

- **Public vs secret fields**  
  API responses must expose only flags like:

```text
api_token_set = true
```

Never return raw secrets.

---

## 2. Secret handling

- Store secrets **only server-side** (SQLite)
- Never expose secrets in:
  - API responses
  - logs
  - error messages

- Use redaction helpers (e.g. `*_redact_secrets`)

- Support **rotation**:
  - allow clearing/replacing secrets
  - define whether cache invalidates on change

---

## 3. Test connection

- Use a **lightweight API call** (e.g. version endpoint)
- Enforce **strict timeouts**
- Return **actionable errors**:
  - HTTP status
  - auth failure
  - TLS issues

- Must be:
  - safe
  - idempotent
  - non-mutating

---

## 4. Manual sync

- Heavy work must run in a **CLI worker**:

```text
api/<connector>_sync_worker.php
```

- Do not rely on HTTP requests for long-running work

- Ensure:
  - bounded execution (pages, rows, time)
  - resumable runs

- Persist status:

```text
last_sync_started_at
last_sync_completed_at
last_sync_status
last_error
```

---

## 5. Scheduled sync and freshness

- Scheduler runs under system user (e.g. `surveytrace`)
- Must:
  - read worker scripts
  - open SQLite DB

- Use consistent path resolution (`install_root()`)

---

### Due logic

- Compute due state using SQLite:

```sql
datetime('now')
```

Avoid mixing time sources.

---

### Locking

- Use row-level locks:

```text
scheduled_*_lock
```

- Prevent overlap between:
  - manual runs
  - scheduled runs

- Always clear locks on failure

---

### Freshness

- Derived from:

```text
cache age vs configured interval
```

- Not browser timers

---

## 6. Local cache tables

- Use:
  - normalized columns for joins
  - JSON for flexible vendor data

- Add tables via:

```text
api/db.php migrations
```

- Keep:

```text
sql/schema.sql
```

aligned for new installs

---

### Retention

Define behavior for upstream deletions:

- hard delete
- soft tombstone

Must be documented per connector

---

## 7. Matching and linking

Use a link table:

```text
<connector>_asset_links
```

Fields:

- `asset_id`
- upstream id
- `match_method`
- `confidence`
- `last_matched_at`
- `is_manual`

---

### Matching rules

- deterministic ordering
- stable assignment
- documented tie-breaking

---

### Rematching

- recompute non-manual links after sync
- preserve manual overrides

---

## 8. Review queue

Expose endpoints for:

- low-confidence matches
- conflicting matches

Allow:

- manual link
- unlink
- re-validation

All actions must be audited.

---

## 9. Preview and apply workflow

For any mutation of operator-controlled data:

- require:
  - preview step
  - explicit confirmation (`confirm: true`)
  - staleness checks

---

### Audit requirement

Log actions with enough detail to reconstruct:

```text
who changed what and why
```

---

## 10. Audit logging

- Use structured events:

```text
source.action
```

Examples:

- `zabbix.link_manual`
- `zabbix.apply_scope_map`

- Never log secrets

---

## 11. API and UI exposure

### Asset enrichment

- `GET /api/assets.php` must be:
  - read-only
  - derived from cache + link tables

- No hidden writes

---

### Connector API

Provide a dedicated endpoint:

```text
/api/<connector>.php
```

Supports:

- configure
- test
- sync
- status

Must enforce:

- CSRF protection
- role-based access

---

### UI pattern

- **Integrations** → config + health
- **Enrichment** → operator workflows

---

## 12. Export and reporting behavior

### Push integrations

If emitting events:

- keep payloads structured
- include:
  - `asset_id`
  - source identifiers
  - conflict indicators

Avoid raw vendor payloads unless size-limited.

---

### Reporting

Define clearly:

- live data vs snapshot data
- where connector data appears

---

## 13. Failure handling

- Must be **non-blocking**
- Failures should:
  - not affect scans
  - not break unrelated APIs

---

### Status handling

Degrade to:

- not configured
- stale
- error

---

### Backoff

Optional:

```text
next_sync_at
```

to avoid repeated failures

---

### Spawn failures

- must:
  - clear locks
  - persist `last_error`

---

## 14. Security checklist

- [ ] Secrets never returned from APIs
- [ ] Logs and errors redact sensitive data
- [ ] TLS verification enforced (no silent bypass)
- [ ] SQL is safe and parameterized
- [ ] RBAC enforced for all actions
- [ ] Sync volume is rate-limited
- [ ] Worker scripts readable by scheduler user
- [ ] File permissions align with setup/deploy policy

---

## Reference: Zabbix mapping

| Guide topic | Zabbix reference |
|-------------|------------------|
| Config + secrets | `zabbix_connector`, `st_zabbix_connector_save`, `st_zabbix_connector_public` |
| Test / sync | `POST /api/zabbix.php`, `api/zabbix_sync_worker.php` |
| Schedule + locks | `sync_schedule_enabled`, `next_sync_at`, `scheduled_sync_lock`, `scheduler_daemon.py` |
| Cache tables | `zabbix_hosts`, interfaces, groups, tags |
| Links + review | `zabbix_asset_links`, match review APIs |
| Preview / apply | `preview_scope_map`, `apply_scope_map`, identity workflows |
| Output | `zabbix_output_worker.php` |

---

## Summary

All connectors in SurveyTrace follow the same structure:

```text
config → sync worker → cache → link → review → apply → enrich → report
```

Consistency across connectors ensures:

- predictable behavior
- easier debugging
- safer integrations