# Worker / job execution substrate — design

This document specifies a **shared execution substrate** for SurveyTrace background work **before** implementing the [Credentialed Checks Engine](CREDENTIALED_CHECKS_ENGINE.md). It is **design only** — no implementation in this deliverable.

**Principles**

- **Additive only** — new SQLite tables and libraries; no broad rewrite of `scan_jobs`, scanner semantics, or systemd as the primary process supervisor.
- **SQLite-compatible** — practical row sizes, indexes, and lease patterns suitable for single-node or small deployments.
- **Explicit operator workflows** — cancellation, retries, and failures are visible and explainable.
- **Observable failure states** — structured error codes, execution logs, and System Health hooks.
- **Safe precursor to credentialed checks** — bounded execution, audit trail, and queue semantics shared with future authenticated checks without entangling them with scan internals prematurely.

**Related:** [Trusted data model](TRUSTED_DATA_MODEL.md) (reconciliation runs vs this substrate’s `worker_job_*` — different concepts, may later link) · [Credentialed Checks MVP plan](CREDENTIALED_CHECKS_MVP_PLAN.md) (worker invocation decisions) · [Worker execution MVP plan](WORKER_EXECUTION_MVP_PLAN.md) (staged implementation) · [Roadmap](../ROADMAP.md#worker-and-job-execution-substrate)

---

## 1. Purpose

SurveyTrace already runs **several** background-style workflows (scans, ingest, scheduled pulls, reconciliation). Today they use **different** patterns: database flags, systemd units, PHP CLI one-shots, Python daemons, and append-only logs. That fragmentation makes it harder to:

- expose **consistent** queue depth, retries, and failures in **System Health**;
- implement **cooperative cancellation** and **lease recovery** the same way everywhere;
- add **credentialed checks** without inventing a third ad-hoc queue model;
- reason about **auditability** (what ran, why it failed, who asked for cancel).

A **small shared substrate** defines common **job states**, **worker liveness**, **attempts**, **error codes**, and **event logs** so new work (ingest adapters, cred checks, optional Zabbix migration) can **opt in** gradually while **scan/collector** behavior stays stable by default.

---

## 2. Current background workflows

| Workflow | Typical process | Persistence today (illustrative) |
|----------|-----------------|----------------------------------|
| **Scanner daemon** | `surveytrace-daemon` — executes scan steps from queue / DB | Scan jobs, `scan_log`-style artifacts, daemon logs |
| **Scheduler daemon** | `surveytrace-scheduler` — schedules scans, may spawn workers | `scan_jobs`, cron-like state in DB |
| **Collector ingest** | `surveytrace-collector-ingest` — merges collector payloads into master | Ingest queue / job rows (product-specific), SQLite |
| **Zabbix sync worker** | `php api/zabbix_sync_worker.php` (scheduler-triggered or manual) | `reconciliation_runs` / Zabbix cache tables, logs |
| **Zabbix output worker** | `php api/zabbix_output_worker.php` | Metrics push, logs |
| **Trusted data reconciliation** | Lazy on read and/or batch PHP paths | `reconciliation_runs`, `asset_observations`, assertions |
| **Future credentialed checks** | Planned dedicated worker or subprocess | Not implemented; should **reuse** substrate once present |

**Design constraint:** the substrate **does not replace** these processes on day one; it **wraps or mirrors** work units where adapters opt in.

---

## 3. Common job lifecycle

States for a **logical work unit** managed through the substrate (one row in `worker_jobs` or equivalent):

| State | Meaning |
|-------|--------|
| **queued** | Eligible to run; no lease held. |
| **leased** | A worker has claimed the job (lease token + expiry); not yet marked running. |
| **running** | Worker reports active execution (heartbeat tied to attempt). |
| **retrying** | Attempt failed with **retryable** error; backoff applied; will re-enter **queued** (or **leased**) when due. |
| **completed** | Success; terminal. |
| **failed** | Terminal failure after max attempts or non-retryable error. |
| **cancelled** | Operator (or policy) requested cancel; worker cooperatively stopped; terminal. |
| **expired** | Lease expired without progress / heartbeat; job returned to **queued** or marked **failed** per policy (document as **recovery**, not a user-facing “success”). |

**Note:** Existing `scan_jobs.status` values may **map** into these over time via an adapter layer; the substrate does not require renaming legacy columns in the first slice.

---

## 4. Common worker lifecycle

Describes a **worker process** or **logical node** (single host may run multiple worker types):

| State | Meaning |
|-------|--------|
| **starting** | Process up; not yet sent first heartbeat / registration. |
| **healthy** | Heartbeat within SLA; consuming or eligible to consume work. |
| **stale** | No heartbeat within threshold; leases may be eligible for recovery. |
| **degraded** | Running but reporting reduced capacity (e.g. disk pressure); optional. |
| **error** | Worker process crashed or failed self-check; may restart via systemd. |
| **stopped** | Graceful shutdown; no new leases. |

**systemd** remains the **supervisor**; heartbeats are **telemetry** for health UI and lease safety, not a replacement for `systemctl`.

---

## 5. Proposed schema (additive, SQLite)

Practical tables (names indicative):

### `worker_nodes`

| Column | Notes |
|--------|------|
| `id` | PK |
| `node_key` | Stable string: `host:service` or UUID |
| `worker_type` | `collector_ingest` \| `cred_check` \| `zabbix_sync` \| … |
| `pid` | optional |
| `metadata_json` | version, hostname, caps |
| `created_at`, `last_seen_at` | |

### `worker_heartbeats`

| Column | Notes |
|--------|------|
| `id` | PK |
| `worker_node_id` | FK |
| `ts` | heartbeat time |
| `status` | healthy / degraded / … |
| `detail_json` | queue depth self-reported, build id |

*Alternative:* fold latest heartbeat into `worker_nodes.last_seen_at` only for MVP; separate table if history needed.

### `worker_jobs`

| Column | Notes |
|--------|------|
| `id` | PK |
| `job_type` | discriminator: `collector_ingest`, `cred_check_run`, … |
| `correlation_id` | optional link to legacy `scan_jobs.id`, ingest id, etc. |
| `payload_json` | opaque but size-bounded pointer to domain row |
| `state` | queued / leased / running / retrying / … |
| `priority` | integer, default 0 |
| `lease_owner` | worker_node_id or lease token string |
| `lease_expires_at` | |
| `attempt_count` | |
| `max_attempts` | |
| `next_run_at` | for backoff |
| `cancel_requested_at` | nullable |
| `created_at`, `updated_at` | |

Indexes: `(state, next_run_at)`, `(job_type, state)`, `(lease_expires_at)` for sweeper.

### `worker_job_attempts`

| Column | Notes |
|--------|------|
| `id` | PK |
| `worker_job_id` | FK |
| `attempt_no` | 1-based |
| `started_at`, `finished_at` | |
| `outcome` | success / fail / cancel |
| `error_code` | structured enum (see §6) |
| `error_message_safe` | no secrets |
| `metrics_json` | duration_ms, bytes, rows |

### `worker_job_events`

Append-only audit stream for **execution** (distinct from user audit log):

| Column | Notes |
|--------|------|
| `id` | PK |
| `worker_job_id` | FK |
| `event_type` | `state_transition` \| `lease_acquired` \| `heartbeat` \| `retry_scheduled` \| … |
| `payload_json` | small |
| `created_at` | |

### MVP slice 1 — physical schema (implemented)

The following matches **`st_migrate_worker_execution_substrate_v1()`** in `api/db.php` and **`sql/schema.sql`** (fresh installs). Migration marker: **`config.migration_worker_execution_substrate_v1 = 1`**.

**Naming vs earlier sketch:** jobs use a single column **`status`** (not `state`); attempt counter fields are **`attempts`** / **`max_attempts`**; scheduling uses **`next_attempt_at`**; correlation uses **`entity_type`** + **`entity_id`** (integer); lease uses **`lease_node_id`** + **`lease_token`** + **`leased_at`**. **`worker_nodes`** carry `hostname`, **`role`**, and **`meta_json`** (no separate `worker_type` on the node row — process type is on **`worker_heartbeats.worker_type`**).

**`worker_nodes`:** `id`, `node_key` (UNIQUE), `hostname`, `role`, `status`, `meta_json`, `created_at`, `updated_at`.

**`worker_jobs`:** `id`, `job_type`, `entity_type`, `entity_id`, `status`, `priority`, `lease_node_id`, `lease_token`, `leased_at`, `lease_expires_at`, `attempts`, `max_attempts`, `next_attempt_at`, `cancel_requested_at`, `error_code`, `error_message`, `payload_json`, `result_summary_json`, `created_at`, `updated_at`, `finished_at`.

**`worker_job_attempts`:** `id`, `job_id`, `attempt_no`, `node_id`, `status`, `started_at`, `finished_at`, `error_code`, `error_message`, `metrics_json`, **UNIQUE(`job_id`, `attempt_no`)**.

**`worker_job_events`:** `id`, `job_id`, `attempt_id`, `event_type`, `level`, `message`, `details_json`, `created_at`.

**`worker_heartbeats`:** `id`, `node_id`, `worker_key`, `worker_type`, `status`, `heartbeat_at`, `details_json`.

**Indexes (summary):** `worker_nodes(status, updated_at)`, `worker_jobs(status, next_attempt_at)`, `(job_type, status, created_at)`, `lease_expires_at`, `created_at`; attempts by `job_id` / `node_id`; events by `job_id` / `event_type`; heartbeats by `node_id` / `worker_type`.

---

## 6. Error model

Structured `error_code` (string enum; extensible):

| Code | Typical use |
|------|-------------|
| `transport_error` | Network, SSH, WinRM channel failure |
| `auth_error` | Credentials rejected |
| `timeout` | Wall or per-phase timeout |
| `policy_blocked` | Rate limit, concurrency cap, allowlist violation |
| `validation_error` | Payload/schema mismatch |
| `dependency_missing` | Required table, file, or peer service unavailable |
| `storage_error` | SQLite busy, disk full, WAL issue |
| `internal_error` | Unexpected exception (logged with reference id) |

**Mapping:** adapters translate legacy exceptions into these codes for UI and health.

**Helper libraries (MVP slice 2):** `api/lib_worker_jobs.php` exposes `st_worker_*` PDO helpers (`st_worker_tables_ready`, `st_worker_register_node`, `st_worker_heartbeat`, `st_worker_enqueue_job`, `st_worker_lease_next_job`, attempt/job finish helpers, `st_worker_request_cancel`, `st_worker_log_event`). `daemon/worker_jobs.py` mirrors the same primitives for `sqlite3.Connection` callers. Invalid `error_code` values on attempts are coerced to `internal_error`. No production workflow loads these modules until adapters opt in (see [MVP plan](WORKER_EXECUTION_MVP_PLAN.md), slices 4 onward).

---

## 7. Retry model

- **max_attempts** — per `job_type` default + optional per-job override (capped).
- **backoff** — exponential with jitter; bounds e.g. min 5s, max 15m (product constants).
- **terminal failure** — `attempt_count >= max_attempts` OR non-retryable error code.
- **Retryable vs non-retryable** — table or function: e.g. `auth_error` and `validation_error` **non-retryable**; `timeout` and `storage_error` **retryable** up to cap.
- **Stale lease recovery** — periodic sweeper: if `state = leased|running` and `lease_expires_at < now`, transition to **queued** (increment attempt or mark `retrying`) or **failed** if attempts exhausted; emit `worker_job_events`.

---

## 8. Cancellation model

- **Requested cancellation** — operator or API sets `cancel_requested_at` on `worker_jobs`; worker polls this flag **between** coarse steps (cooperative).
- **Cooperative cancellation** — no forced `SIGKILL` of arbitrary subprocesses in MVP; long steps should check cancel flag.
- **Already-running limitations** — in-flight SSH session may run to timeout; UI copy: “Cancel requested — will stop after current step.”
- **Audit** — user audit stream: `worker_job.cancel_requested` with actor; execution stream: `state_transition` → `cancelled`.

---

## 9. Logging and audit

| Layer | Purpose |
|-------|--------|
| **Operator audit events** | Who changed credentials, who started a cred check job (`user_audit_log` pattern) — business accountability. |
| **Execution logs** | `worker_job_events` + `worker_job_attempts` — technical trace of state machine. |
| **Debug logs** | `journalctl`, file logs — developer detail; **must not** contain secrets; not a substitute for structured events. |
| **scan_log compatibility** | Scan-specific human or structured logs **remain** for scan jobs; substrate can **reference** `scan_jobs.id` without replacing `scan_log` storage in MVP. |

---

## 10. Migration strategy (gradual adoption)

Order minimizes risk to core revenue paths (scanning):

1. **Collector ingest first** — bounded queue, clear retries, visible in health; **MVP slice 4** mirrors ingest into `worker_jobs` / `worker_job_events` (`job_type = collector_ingest`) for System Health while **`collector_ingest_queue` stays authoritative**.
2. **Credentialed checks next** — new feature; native `job_type` from day one when implemented.
3. **Zabbix sync later** — optional adapter; today’s `reconciliation_runs` can coexist; map sync runs to `worker_jobs` for visibility only (dual-write) before any move of execution.
4. **Scanner / scheduler jobs last or never** — highest risk; prefer **read-only mirroring** of state into `worker_jobs` for health dashboards only, unless a later design proves full migration safe.

---

## 11. UI / System Health

Expose a compact **read-only** snapshot (extend existing health JSON pattern):

- **Queue depth** — count by `job_type` and `state` for `queued` + `retrying`.
- **Stale workers** — `worker_nodes` / heartbeats older than threshold.
- **Failed jobs** — count in last 24h by `error_code`.
- **Retrying jobs** — count + oldest `next_run_at`.
- **Oldest queued job** — `min(created_at)` where `state=queued`.

**UI (MVP slice 3, implemented):** `GET /api/health.php` includes **`worker_substrate`** (`st_worker_substrate_health_snapshot()` in `api/lib_worker_jobs.php`). The System health tab shows **Background jobs (preview)** with status, job counts, heartbeat / stale-node counts, oldest queued/running ages, 24h failure/event counts, and last error text. Empty healthy substrate stays a single quiet line; warn/error states use existing `st-health-band--attention` styling and surface hints under **Needs attention**.

### Clearing old terminal `worker_jobs` (e.g. setup failures)

1. **Supported prune (time-based, dry-run first)** — removes terminal `worker_jobs` (and related events/attempts/runs when included) older than a cutoff:

   ```bash
   php /opt/surveytrace/scripts/prune_operational_history.php \
     --db=/opt/surveytrace/data/surveytrace.db \
     --older-than-days=1 \
     --include-runs
   ```

   Review output, then add **`--apply`**. Do **not** use `--older-than-days=0` (cutoff becomes “now” and can match almost all terminal history).

2. **Surgical delete (specific IDs)** — only if you know the rows are disposable (e.g. ids 7–12). Clear FK references first, then children, then the job:

   ```sql
   UPDATE credential_check_runs SET worker_job_id = NULL
     WHERE worker_job_id IN (7,8,9,10,11,12);
   DELETE FROM worker_job_events WHERE job_id IN (7,8,9,10,11,12);
   DELETE FROM worker_job_attempts WHERE job_id IN (7,8,9,10,11,12);
   DELETE FROM worker_jobs WHERE id IN (7,8,9,10,11,12);
   ```

   Run inside `sqlite3` with a backup first if unsure.

### Tuning the “failed jobs” health hint

**Settings UI (preferred):** **Settings → Platform → Security controls** — set **Failed worker jobs warn threshold** (same `config` key as below) and click **Save security controls**.

Optional direct **`config`** row:

| key | value | effect |
|-----|-------|--------|
| `health_worker_substrate_warn_failed_jobs_min` | `1` (default if unset) | Warn when `failed_jobs` ≥ 1 (original behavior). |
| | `25` | Warn only when there are at least 25 failed rows. |
| | `0` or `disabled` | Never add the “N job(s) in failed state” hint (counts still shown; separate **error** rules still apply for very large totals). |

Example (SQL only if you prefer not to use the UI):

```sql
INSERT OR REPLACE INTO config (key, value) VALUES ('health_worker_substrate_warn_failed_jobs_min', '25');
```

**Credentialed checks (MVP slice 7):** `GET /api/health.php` includes **`credential_check_runs`** (`st_cc_health_snapshot_runs()` in `api/lib_credential_check_ops.php`) — queued/active/running, **completed (24h)**, and **failed (24h)**. Runs use `job_type = credentialed_check`; **`credential_check_worker.py`** executes **`ssh.linux.os_release@1.0.0`** when selected (otherwise targets stay skipped `not_implemented`), unless **`SURVEYTRACE_CRED_CHECK_PLACEHOLDER_ONLY=1`**.

---

## 12. MVP adoption plan

Recommended **first implementation slice**:

1. **Schema only** — create tables; no behavior change (**done** — slice 1).
2. **Helper library** — PHP `lib_worker_jobs.php` + Python `worker_jobs.py` (**done** — slice 2); no production callers yet.
3. **Health visibility** — `health.php` (or lib) reads counts; empty tables = quiet (slice 3).
4. **One adapter** — either **collector ingest** (highest operational payoff) **or** a thin **credentialed-check** stub that only enqueues dry-run jobs — pick one per sprint capacity (slice 4/5).

Second slice: sweeper cron or systemd timer + retry backoff columns in use.

---

## 13. Deferred

- **Distributed queue brokers** — Redis, RabbitMQ, SQS.
- **Kubernetes** orchestration for workers.
- **Full rewrite** of `scan_jobs` into generic rows only.
- **Replacing systemd** with in-app supervisor.
- **Cross-region** multi-master execution.

---

## Validation

- This file is documentation only.
- Implementation must follow [SurveyTrace design approach](../ROADMAP.md#design-approach): explicit workflows, stable models, visibility.
- Staged coding plan: [Worker execution MVP plan](WORKER_EXECUTION_MVP_PLAN.md).
