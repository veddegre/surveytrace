# Credentialed Checks Engine — design

This document specifies the **SurveyTrace Credentialed Checks Engine** before implementation. It aligns with the platform’s **trusted data model** ([Trusted data model](TRUSTED_DATA_MODEL.md): observations, assertions, confidence, evidence linkage, reconciliation) and with the capability track described under **Credentialed checks engine** in [Roadmap](../ROADMAP.md).

**Design principles**

- Explicit operator workflows; no background “surprise” automation.
- Least privilege: credentials and checks scoped narrowly; defaults deny.
- Auditable execution: who ran what, against which target, with which outcome.
- Safe credential handling: encryption at rest, no secret echo in APIs/UI/logs.
- Bounded runtime: timeouts, caps, concurrency limits, cancellation.
- Structured evidence output: schemas, artifacts, normalization — not unstructured blobs as the sole truth.
- Integration with trusted data: checks feed **observations**; **assertions** change only via reconciliation rules operators can understand.
- Clear failure states: transport, auth, plugin, policy, and resource limits are distinguishable in UI and audit.

---

## 1. Purpose and scope

### What credentialed checks are

**Credentialed checks** are **authenticated, in-scope collection actions** initiated by operators. They use stored **credential profiles** and implemented transports (**SSH** and **SNMPv3** in this release) to run **bounded plugins** on a **target asset or device**, producing **structured results** and **evidence artifacts** that SurveyTrace normalizes and ties to the trusted data path.

They are **not** passive ingestion of a third party’s already-chewed summary; they are **SurveyTrace-executed** operations with a clear blast radius and audit trail.

### How this differs from other SurveyTrace surfaces

| Surface | Role relative to credentialed checks |
|--------|----------------------------------------|
| **Active network scanning** | Unauthenticated or limited-auth **network** discovery (ports, banners, fingerprints). No assumption of host login. Different trust boundary and evidence types. |
| **Read-only API enrichment** | Pulls **vendor/API** inventory or config (see [Roadmap](../ROADMAP.md) — *Infrastructure / API connectors*). No shell on the endpoint; different auth (API tokens, service accounts to *platforms*). |
| **Zabbix monitoring enrichment** | Cached **monitoring system** data (items, inventory fields, problems). Not SurveyTrace executing arbitrary in-host logic; sync/match/review/apply pattern ([Roadmap](../ROADMAP.md) — *Monitoring enrichment* / *Connector framework*). |
| **Future Defender / ownership connectors** | External **security / ITSM** context ([Roadmap](../ROADMAP.md) — *Ownership and endpoint enrichment*). Telemetry or ownership, not first-class “run this check on host X with profile Y” unless explicitly modeled later. |

**In scope for this engine:** defining jobs, transports, plugins, credentials, results, artifacts, audit, and trusted-data handoff.

**Out of scope for this document:** implementing transports, vault products, or compliance frameworks (see [§13](#13-deferred-work)).

### Collectors, scans, and scheduling (shipped behavior)

Credentialed checks **execute on the master** via **`surveytrace-credential-check-worker`** (see [Credentialed checks integration](wiki/credentialed-checks-integration.md)). **Collectors** do not perform credentialed checks. **Normal scans** and **`scan_schedules`** do **not** automatically enqueue credentialed jobs.

**Per-job recurring schedules (Phase 1):** `credential_check_jobs` may set `schedule_enabled`, `schedule_cron`, `schedule_timezone`, and related columns. The **`surveytrace-scheduler`** service invokes **`scripts/credential_schedule_tick.php`** each poll cycle. That PHP tick selects due jobs, respects **`max_concurrency`** (max simultaneous active runs per job), calls the same **`st_cc_run_launch()`** path used for manual runs (so **`worker_jobs`** + audits stay unified), sets **`credential_check_runs.launch_source`** to `scheduled`, advances **`schedule_next_run_at`** using the same cron semantics as `daemon/scheduler_daemon.py` (see `api/lib_credential_schedule.php`), and writes bounded audit rows. **Catch-up:** after downtime, at most **one** overdue run is created per due evaluation; **`schedule_next_run_at`** is then recomputed from current UTC time (no backlog storm). **Cron limitations** match the Python scheduler helper: five fields or `@hourly` / `@daily` / `@weekly` / `@monthly` / `@yearly` presets; `*` steps, ranges, and lists; no `L`/`W`/`#` or month/day names.

---

## 2. Execution model

Definitions:

| Concept | Definition |
|--------|------------|
| **Check job** | A **logical intent**: which targets (assets/devices or scope), which **credential profile** (or ordered fallback list), which **plugins** (and versions), schedule or ad-hoc, and policy knobs (timeouts, concurrency). Persists as a template or one-shot definition. |
| **Target asset/device** | Primary **asset** (`assets.id`, IP/identity) or **device** (logical grouping). Resolution rules: job specifies asset list or scope; executor resolves to concrete endpoints (IPs, management interfaces). |
| **Credential profile** | Named bundle: transport type, principal identity (username, community user, etc.), **secret material by reference** (encrypted blob or external ref in future), scope tags, allowed transports/plugins. Never returned verbatim via API. |
| **Transport** | Mechanism to reach the host: **SSH** and **SNMPv3** are implemented; **WinRM** remains deferred. Pluggable conceptually; each enforces auth and channel limits. |
| **Plugin/check** | Versioned unit of work: declared inputs, **allowlisted operations** (e.g. read-only file paths, specific OIDs), max output size, required privilege hint, output JSON schema. |
| **Evidence artifact** | Opaque or semi-opaque **blob** (stdout capture, SNMP walk fragment, file excerpt) stored with **hash**, size, MIME hint, and **redaction** metadata. Linked to a **run** and optionally to a **result** row. |
| **Result normalization** | Plugin raw output → **typed fields** (packages, OS string, finding records) + **proposed observations** payload. Failures here are **soft failures** (artifact kept, result status `partial` / `normalize_error`). |

**Lifecycle (conceptual):** `job` → queued `run` → per-target **attempts** → **results** (+ **artifacts**) → normalization → **observation** writes (and optional **finding** rows) → reconciliation may update **assertions** later — never direct overwrite of assertions by the plugin alone.

---

## 3. Supported transports (initial design)

### SSH

- **Useful for:** Linux/Unix **package inventory**, **os-release**, static config snippets (allowlisted paths), service list (allowlisted), file metadata where policy allows.
- **Authentication model:** host key policy explicit (known fingerprints / TOFU with operator confirmation); user key or password via profile (password strongly discouraged for MVP except vault-backed future); `sudo` only if plugin declares it and job allows elevated tier.
- **Expected evidence:** JSON lines + optional raw transcript artifact (redacted); file hashes optional later.
- **Failure modes:** connection refused, host key mismatch, auth failure, channel open limit, sudo denied, disk full on target, command not found (plugin prerequisite).
- **Safety limits:** no interactive TTY; max sessions per target per hour; max wall time; max bytes stdout/stderr; **command allowlist** only (no free-form shell for MVP).

### WinRM

- **Useful for:** Windows **patch level**, installed software registry slices, service list, WinRM metadata — when product commits to PowerShell remoting constraints.
- **Authentication model:** TLS to WinRM; NTLM/Kerberos/Certificate as product policy; credential profile stores **type** + secret ref; double-hop explicitly **out of scope** for MVP.
- **Expected evidence:** structured JSON from constrained PowerShell modules; transcript artifacts heavily redacted (secrets scrubbed).
- **Failure modes:** TLS errors, auth failure, WinRM not enabled, firewall, constrained language mode blocking cmdlet.
- **Safety limits:** constrained runspace / fixed cmdlet surface for MVP; timeouts; output caps; no arbitrary script path execution.

### SNMPv3

- **Useful for:** **device identity** (sysName, sysObjectID, sysDescr), engine ID, limited MIB walks for inventory-class OIDs when allowlisted.
- **Authentication model:** user + **auth** + **priv** protocols (e.g. SHA/AES); engine ID discovery; context name if needed.
- **Expected evidence:** OID→value map JSON + small BER artifact optional.
- **Failure modes:** wrong user, auth/priv failure, timeout, engine ID mismatch, OID not implemented, rate-limited device.
- **Safety limits:** OID allowlist per plugin; max varbinds; walk depth; packet rate per target; read-only **SNMPv3** (no SET in MVP).

---

## 4. Credential model

### Credential profiles

- **Named**, versioned **logical** credential: `transport`, `principal`, `metadata` (non-secret: realm, port override, SNMP security level).
- **MVP slice 3–5 (implemented):** `GET/POST /api/credential_profiles.php` (admin-only) manages **metadata** (`principal_json` / `scope_json` — still no secret fields in principal), **optional encrypted secrets** (`set_secret` / `clear_secret`), and **transport handshake tests** (`action=test` — **SSH** and **SNMPv3** only; **WinRM** deferred). On hardened installs, **`api/lib_cred_secret_helper.php`** runs **`daemon/cred_secret_ops_cli.php`** as **`surveytrace`** via **`sudo -n`**; the helper decrypts inside that boundary and passes **short-lived JSON on stdin** to **`daemon/cred_transport_cli.py`** (Python **paramiko** / **pysnmp**). **No plugins**, **no worker_jobs**, **no observations**. UI: **Settings → Credentialed checks — profiles**. Envelope crypto: **libsodium secretbox** (preferred) or **OpenSSL AES-256-GCM**; responses expose `has_secret`, `secret_status`, redacted `secret_envelope`, `last_test_*` — never ciphertext, plaintext, or stack traces.
- **Secret storage:** versioned **envelope JSON** in `credential_profiles.secret_ciphertext`; **key material** is loaded from **`/etc/surveytrace/surveytrace.env`** (or equivalent) for **`surveytrace`** and the helper — **not** from **`www-data`**-readable paths (see [MVP plan](CREDENTIALED_CHECKS_MVP_PLAN.md) slice 4 and [Troubleshooting — security model](wiki/troubleshooting.md#credential-secret-helper--security-model)). OS vault / HSM deferred.
- **Operational key model:** every process that **decrypts** stored envelopes must use the **same** `SURVEYTRACE_CRED_SECRET_KEY` value (credential-check **worker** + **`daemon/cred_decrypt_cli.php`**, and the **secret helper** CLI). **`PHP-FPM` / Apache pools do not need `SURVEYTRACE_CRED_SECRET_KEY` in their own environment** for normal **`set_secret` / `clear_secret` / `action=test` / encryption status** when sudoers and **`cred_secret_ops_cli.php`** are configured; injecting the key into **`php-fpm`** is unnecessary and increases blast radius. Strict key parsing can be enforced with `SURVEYTRACE_CRED_SECRET_KEY_STRICT=1`.
- **Lifecycle maintenance:** secret envelope rewrap is operator-triggered (manual dry-run/apply utility) and is recommended after envelope-format hardening or key policy tightening; no automatic rotation daemon in this release.
- **Scoped credentials:** profiles attach to **allowed scope_ids**, **asset tags**, or explicit **asset allowlists**. Deny by default if unset (product choice: “explicit allowlist only” for MVP is safest).
- **Rotation:** operators mark `rotated_at` / `expires_at`; jobs warn on expiry; **no auto-rotation** in MVP.
- **RBAC:** separate permissions, e.g. `credential:read_meta`, `credential:create`, `credential:test`, `check:run`, `check:review`. Viewing **metadata** ≠ using credential in a run (both audited).
- **Audit logging:** every create/update/delete/test/run references `credential_profile_id` (not secret).
- **Never expose secrets:** APIs return `has_secret`, encryption **key_fingerprint** (hash prefix of derived key, not the configured string), `last_test_status`, `last_test_error_code`, `last_test_duration_ms`, and envelope metadata — never plaintext passwords or private keys. Logs store **result codes** and **redacted** excerpts only.

### Credential test (handshake)

- **Dedicated** `POST` `action=test`: explicit **target_host** (not persisted); SSH runs fixed **`true`** then bounded **`uname -s`**; SNMPv3 single GET **sysDescr.0** only. **Short timeouts**, global **non-reentrant flock** to limit parallel tests, safe error taxonomy (`auth_failed`, `timeout`, `host_key_mismatch`, …). Audits: `credential_profile.test_started`, `.test_succeeded`, `.test_failed`. **SSH host key policy (handshake):** **`SURVEYTRACE_CRED_TRANSPORT_HANDSHAKE=1`** forces **AutoAddPolicy** for first-connect tests (see **`daemon/cred_transport_ssh.py`**). **Production cred SSH workers** use **`SURVEYTRACE_CRED_SSH_CHECK_HOST_KEY_POLICY`** when set, else **`SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY`** (see **`daemon/cred_check_ssh_os_release.py`**). **WinRM** handshake not in this slice.

---

## 5. Plugin/check framework

### Plugin manifest (conceptual)

- `id`, `version`, `transport` (`ssh` \| `winrm` \| `snmpv3` \| `api`), `title`, `description`
- `inputs_schema` (JSON Schema): host parameters only (paths, boolean flags allowed by policy)
- `timeout_ms_default`, `timeout_ms_max`
- `privilege`: `none` \| `low` \| `elevated` (elevated requires job flag + RBAC)
- `output_schema_version`, `output_schema` (JSON Schema for normalized payload)
- `remediation`: optional structured hints (KB IDs, package names, doc links) — **informational**, not executable in MVP
- `state`: `disabled` \| `stable` \| `experimental` (experimental hidden unless admin enables)
- `allowlisted_operations`: declarative list (e.g. fixed argv templates, fixed OIDs)

### Built-in registry (MVP slice 2 — implemented)

- **Storage:** `credential_check_plugins.manifest_json` holds the full normalized manifest (schemas, timeouts, caps, allowlisted operations). Columns `plugin_key`, `version`, `transport`, and `state` duplicate key fields for queries.
- **Seeding:** `api/lib_credentialed_checks.php` defines built-ins (`ssh.linux.os_release`, `ssh.linux.package_inventory`, `snmpv3.device_identity`) and upserts on `(plugin_key, version)` without deleting operator-added rows.
- **Read API:** `GET /api/credentialed_checks.php` (admin-only) returns metadata only — **no secrets**, no execution.

### Execution rules

- **Timeout:** per-plugin, capped by global max.
- **Output size:** hard cap; truncate with reason in result.
- **Versioning:** job pins `plugin_id@version`; incompatible upgrades require new job definition.
- **Failure:** plugin crash → run marks failed; other targets continue (**failure isolation**).

---

## 6. Data model proposal (additive)

Practical SQLite-oriented tables (names illustrative):

### `credential_check_plugins`

| Column | Notes |
|--------|------|
| `id` | PK |
| `plugin_key` | Stable string, e.g. `linux.packages.dpkg` |
| `version` | Semver |
| `transport` | enum |
| `manifest_json` | Full manifest |
| `state` | disabled / stable / experimental |
| `created_at`, `updated_at` | |

### `credential_profiles`

| Column | Notes |
|--------|------|
| `id` | PK |
| `name` | Operator-visible |
| `transport` | ssh / winrm / snmpv3 |
| `principal_json` | Non-secret fields |
| `secret_ciphertext` | Encrypted blob; **never** selected into generic APIs |
| `scope_json` | Allowed scopes/assets/tags |
| `enabled` | Soft-disable profile without delete |
| `created_by`, `created_at`, `updated_at` | |
| `last_test_at`, `last_test_status` | |

### `credential_check_jobs`

| Column | Notes |
|--------|------|
| `id` | PK |
| `name`, `description` | |
| `credential_profile_id` | FK |
| `target_mode` | `assets` \| `scope` \| `device` |
| `target_json` | IDs or scope filter |
| `plugin_selection_json` | `[{plugin_key, version}]` |
| `policy_json` | timeouts, concurrency, elevated allowed |
| `schedule_cron` | nullable — explicit scheduling only |
| `enabled` | bool |
| `created_by`, `created_at`, `updated_at` | |

### `credential_check_runs`

| Column | Notes |
|--------|------|
| `id` | PK |
| `job_id` | nullable for ad-hoc |
| `worker_job_id` | Optional link to `worker_jobs.id` when execution is enqueued on the substrate |
| `started_at`, `finished_at` | |
| `status` | queued / running / completed / failed / cancelled |
| `initiated_by` | user id or `system` if ever allowed |
| `summary_json` | counts, duration |

### `credential_check_run_targets` (optional normalization)

| Column | Notes |
|--------|------|
| `id` | PK |
| `run_id`, `asset_id` | |
| `status` | per-target |
| `error_code`, `error_message_safe` | no secrets |
| `started_at`, `finished_at` | optional per-target timing |

### `credential_check_results`

| Column | Notes |
|--------|------|
| `id` | PK |
| `run_id` | Logical ref to `credential_check_runs.id` |
| `target_id` | Optional logical ref to `credential_check_run_targets.id` (per-target correlation) |
| `asset_id` | Logical ref to `assets.id` |
| `plugin_key`, `plugin_version` | |
| `status` | success / partial / failed (app-level) |
| `normalized_json` | Schema-validated output |
| `metrics_json` | duration, bytes, retry count |
| `created_at` | |

### `credential_check_artifacts`

| Column | Notes |
|--------|------|
| `id` | PK |
| `result_id` | Logical ref to `credential_check_results.id` |
| `kind` | stdout / stderr / snmp_capture / file_excerpt |
| `storage_path` | Prefer file path for large payloads (nullable) |
| `blob` | SQLite `BLOB` column, quoted identifier `"blob"` in DDL (nullable) |
| `sha256`, `size_bytes` | |
| `redaction_version` | Integer default (e.g. redaction ruleset version) |
| `created_at` | |

SQLite MVP slice 1 does **not** declare foreign keys for these references (consistent with other SurveyTrace additive tables). **`secret_ciphertext`** exists on `credential_profiles` but generic list/get APIs must **never** return it; nothing writes real ciphertext until a later slice wires encryption.

Indexes: `(run_id)`, `(asset_id, started_at)` for host history; `(job_id, started_at)` for job audit.

### Slice 6 — Job templates and queueing (implemented)

Operators define **`credential_check_jobs`** and launch **`credential_check_runs`** from admin APIs/UI. At launch the server **snapshots** targets into **`credential_check_run_targets`**, enqueues **`worker_jobs`** with `job_type = credentialed_check`, `entity_type = credential_check_run`, `entity_id = credential_check_runs.id`, and links `credential_check_runs.worker_job_id`.

APIs: `GET/POST /api/credential_check_jobs.php`, `GET/POST /api/credential_check_runs.php` (admin-only). Cooperative cancel uses `worker_jobs.cancel_requested_at` plus helpers `st_worker_finalize_queued_cancel` / `st_worker_finalize_leased_cancel` / `st_worker_finish_job_cancelled` so queued jobs do not remain stuck non-leaseable after cancel.

### Slice 7 — Bounded SSH `os_release` (implemented)

The Python daemon **`daemon/credential_check_worker.py`** (with **`daemon/cred_check_run.py`**, **`daemon/cred_check_ssh_os_release.py`**, **`daemon/cred_check_ssh_packages.py`** for slice 8, **`daemon/cred_secret_decrypt.py`**, **`daemon/cred_decrypt_cli.php`**) leases credentialed check jobs and, when the job’s **`plugin_selection_json`** includes **`ssh.linux.os_release@1.0.0`** and/or **`ssh.linux.package_inventory@1.0.0`** and the profile transport is **SSH**, runs the corresponding bounded paths — **no PTY**, **no operator-supplied remote command**, **no shell interpolation of user data**. **Asset `ip` only** is used as the SSH target address. Plugins not in the executable set for the transport remain **`skipped` / `not_implemented`** (unless placeholder-only mode).

Secrets are decrypted with the same envelope format as **`api/lib_secrets.php`** by invoking **`daemon/cred_decrypt_cli.php`** (requires **`php`** on the worker host and **`SURVEYTRACE_CRED_SECRET_KEY`** when ciphertext is stored). On success the worker writes **`credential_check_results`** (`normalized_json` includes `os_release`, `normalized_os`, `source: credentialed_check`), a **small bounded stdout `credential_check_artifacts`** row (sha256 + size), and an **`os_version_observed`** row in **`asset_observations`** with recon source **`credentialed_check`** and a stable **`source_object_ref`** (`run:{id}:target:{id}:ssh.linux.os_release@1.0.0`). **No direct `asset_assertions` writes** from the worker.

**Smoke / CI:** set **`SURVEYTRACE_CRED_CHECK_PLACEHOLDER_ONLY=1`** so the worker keeps slice-6-style skips (no SSH, no results) for automated DB fixtures.

**Stabilization / security (audit):**

- **Secrets:** decrypted only immediately before SSH for a target; decrypt helper never logs stderr; worker DB **`worker_jobs.error_message`** on internal failure is a **generic** string (no Python trace / exception text in SQLite).
- **`normalized_json`:** `os_release` map is **sanitized** (sensitive-looking keys stripped, per-key and key-count caps) before insert so a hostile `/etc/os-release` cannot bloat JSON or smuggle obvious secret fields.
- **Run detail API:** returns **`normalized_preview`** (truncated; for **`ssh.linux.package_inventory`** a bounded JSON preview with **`packages_sample`** instead of the full list) and **`metrics`** allowlist only — not raw **`metrics_json`**.
- **SSH:** **`get_pty=False`**; stderr from remote is **not** stored on success (only a length in metrics); SFTP primary + fixed **`cat /etc/os-release`** fallback; host-key policy for **workers** uses **`SURVEYTRACE_CRED_SSH_CHECK_HOST_KEY_POLICY`** (preferred) or **`SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY`** in **`daemon/cred_check_ssh_os_release.py`**. UI handshake uses **`daemon/cred_transport_ssh.py`** with **AutoAddPolicy** when **`SURVEYTRACE_CRED_TRANSPORT_HANDSHAKE`** is set (MITM risk documented for lab tests).
- **No-network test:** `python3 daemon/cred_check_os_release_selftest.py` (parse, caps, normalizer).

**Manual SSH checklist (before package inventory):**

1. Job with **`ssh.linux.os_release@1.0.0`** only; profile **SSH**; asset **`ip`** reachable; **`SURVEYTRACE_CRED_SECRET_KEY`** set on app + worker; **`php`** on worker PATH; **unset** `SURVEYTRACE_CRED_CHECK_PLACEHOLDER_ONLY`.
2. Expect **`credential_check_results`** row, **`credential_check_artifacts`** stdout ≤32 KiB, **`os_version_observed`** upsert, run **`completed`** with mixed target outcomes if some assets fail.
3. Wrong password → target **`auth_failed`**; tiny timeout in job policy → **`timeout`**; **`output_too_large`** → cap manifest / policy and use an artificially huge remote file (lab only).
4. Cancel mid-run → remaining targets **`user_cancelled`**; cancel after all targets finished → run still **`completed`**.
5. GET run detail as admin → no **`secret_ciphertext`**, no full **`normalized_json`**, **`metrics`** only allowlisted keys.

### Slice 8 — Bounded SSH `package_inventory` (implemented)

When **`ssh.linux.package_inventory@1.0.0`** is selected and the profile transport is **SSH**, **`daemon/cred_check_ssh_packages.py`** uses the same Paramiko session policy as slice 7 and runs **only** these fixed remote commands (**`get_pty=False`**, strict timeout, separate stderr cap, stdout truncated at cap instead of failing the whole read):

- **`dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n'`** — tried first; success when exit code **0**.
- **`rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n'`** — used when dpkg does not succeed with exit **0**.

There is **no** operator-supplied argv, **no** shell interpolation from user input, and **no** stderr artifact for MVP (stderr length may appear in **`metrics_json`** only). **`credential_check_results.status`** is **`success`**, **`partial`** (truncated stdout, storage row cap, or parse drops), or **`failed`** (auth, timeout, unsupported OS when neither manager works, etc.). **`normalized_json`** holds **`package_manager`**, **`package_count`**, bounded **`packages[]`**, **`partial`**, **`truncated`**, **`source: credentialed_check`** — field **`parse_dropped`** is metrics-only. **Default parse caps** (overridable via plugin manifest caps when present): **2000** stored rows; **200** / **200** / **64** characters per name / version / arch after sanitization. **`credential_check_artifacts`** stores stdout clipped to **32 KiB** (sha256 of the stored snippet). **`package_inventory_observed`** is written **once per result** as a **summary** (manager / count / digest in **`normalized_value`**; small JSON summary in **`raw_value`**) — **not** thousands of **`package_installed`** rows. **No CVE fusion, no findings, no assertions** from this path; the full bounded list is **evidence** in the check result, not a trusted software assertion.

**Software inventory persistence (normalized):** after each successful **`package_inventory`** result, the worker **deletes legacy** **`software_observed`** rows for that asset + plugin (cleanup from older releases), **upserts** normalized rows into **`software_inventory` / `software_inventory_versions` / `software_inventory_asset_state`** (batched SQLite writes; **active** rows reflect the latest scan; disappeared packages flip **`active=0`**), and writes **one** **`software_inventory_snapshot_observed`** row per target with **diff counts** (`packages_added` / `packages_removed` / `packages_changed`) plus **`active_rows_after`**. **`package_inventory_observed`** and bounded **`normalized_json`** previews stay as today. **No** change to remote commands or parsing caps. **No** CVE/SBOM **from the executor** — see [TRUSTED_DATA_MODEL.md](TRUSTED_DATA_MODEL.md). When normalized persist succeeds, the worker **best-effort enqueues** a deduped **`worker_jobs`** row (`job_type = vulnerability_correlation`, `entity_type = asset`) so operators can drain correlation **offline** via `php scripts/run_vulnerability_correlation.php --consume-jobs` — **no** heavy advisory matching inline during the SSH session.

**Software reconciliation (slice 2 — PHP lazy reconcile):** on host detail (`assets.php` single-asset GET), **`st_recon_lazy_reconcile_software_inventory_summary`** derives **one** **`asset_assertions`** row per asset with **`assertion_type = software_inventory_summary`** (compact label like **`237 packages (dpkg)`**). Evidence inputs include latest **`package_inventory_observed`**, optional **`software_inventory_snapshot_observed`**, **active row count** from **`software_inventory_asset_state`**, and legacy **`software_observed`** (if present). **`assertion_sources`** link the package summary (primary when present), the inventory snapshot when present, and up to **five** legacy **`software_observed`** samples — **never** per-package assertions. **Confidence** is **`low`** \| **`medium`** based on **freshness** (**90-day** stale threshold), partial/truncated/bounded signals — **not** CVSS or exposure. Explanation **must** state **no CVE matching** ran. **Deferred:** CVE correlation, findings, SBOM, dependency graphs, package alerts — unchanged.

**Future investigation (tracked in [Roadmap](../ROADMAP.md#package-advisory-correlation-future)):** how bounded inventory could eventually support **package→advisory** correlation (NVD, OSV, distro trackers, vendor advisories, KEV, EPSS) with identity normalization, precedence, false-positive handling, evidence/audit, scale, and UI wording — subject to **non-negotiable** constraints: no findings from names alone; **`package_inventory_observed`** never vuln authority; normalized identity + advisory confidence before alerts; remediation deferred until match quality is proven.

**Software inventory UX / diagnostics (slice 3):** single-asset JSON adds **`software_inventory_stale`**, **`software_inventory_catalog`** (active row count + latest `last_seen_at` when tables exist), and **`software_inventory_source`**. Host modal copy distinguishes **partial/bounded** inventory from CVE analysis; **View software evidence** shows up to **3** preview rows from the **normalized catalog** (or legacy **`software_observed`** when present). Bounded search: **`GET /api/software_inventory.php?asset_id=&q=`**. **`trusted_data`** adds inventory row totals + latest active `last_seen_at`, plus existing summary diagnostics (**`software_observed_without_summary_assets`** remains for legacy rows). Admin **`recon_diagnostics`** includes read-only **`software_inventory`** (collect + resolve only — **no** lazy upsert). **Deferred:** unchanged — no CVE matching, no per-package assertions, no remediation.

**Software inventory weighting / readiness (no new ingest):** resolver explanations spell out **why** confidence is **`medium`** vs **`low`** (fresh window, partial/truncated/bounded inventory, stale bands **`90_180`** vs **`over_180`**) and call out **`software_inventory_observation_gap`** when `package_inventory_observed` exists without **normalized snapshot / active rows / legacy `software_observed`** corroboration (still **`medium`** when otherwise fresh+complete — diagnostics-first). Single-asset JSON adds **`software_inventory_has_bounded_observations`** (true when corroboration exists), **`software_inventory_observation_gap`**, **`software_inventory_stale_band`**. **`trusted_data`** keeps bounded readiness counters; the “summary without bounded rows” diagnostic now treats missing normalized corroboration like the legacy missing-**`software_observed`** case. Resolver copy reserves future fusion semantics (**scanner / API / SBOM / agent** inventory) without wiring new transports or feeds. Health payloads remain **count-only** — **`st_recon_slice4_assert_health_trusted_software_diag_bounded`** guards contract tests against raw **`packages`** / result blobs on **`trusted_data`**.

**No-network test:** `python3 daemon/cred_check_package_inventory_selftest.py` (parser/sanitizer). **`python3 daemon/software_inventory_selftest.py`** (via **`php scripts/st_software_inventory_normalization_selftest.php`**) covers normalization + persist + diff. **`python3 daemon/st_software_observation_selftest.py`** remains for legacy **`software_observed`** helpers. **`php scripts/st_software_inventory_summary_selftest.php`** covers resolver rules. **`php scripts/st_software_inventory_evidence_selftest.php`** covers API field contract + bounded recon payload rules. **`php scripts/st_software_inventory_diagnostics_selftest.php`** covers stale bands + health **`trusted_data`** leak guards. **`python3 daemon/cred_check_os_release_selftest.py`** remains for os-release. **`php scripts/st_cc_normalized_preview_selftest.php`** asserts admin run-detail preview never exposes the full **`packages`** array (only **`packages_sample`**). Ops: **`php scripts/diagnose_software_inventory.php`** prints table row counts + latest active timestamp. Advisory correlation foundation: **`php scripts/st_vulnerability_correlation_selftest.php`**, **`php scripts/import_advisories.php`**, **`php scripts/run_vulnerability_correlation.php`**, **`php scripts/diagnose_vulnerability_correlation.php`**.

**Storage / retention (operator expectation):** each completed run appends **`credential_check_results`** and **≤32 KiB** stdout **`credential_check_artifacts`** per plugin row; **`normalized_json`** is capped (~2000 package dicts × field caps). **`package_inventory_observed`** upserts **one row per result**; **`software_inventory_snapshot_observed`** adds **one summary row per target** with diff metadata — observation volume stays **O(targets)** per run, not **O(packages)**. **Do not prune** current **`software_inventory_asset_state`** rows as part of routine history pruning; inactive rows are retained for lifecycle/diff semantics. Prune old **runs** / observations / artifacts per existing ops policy.

### Slice 9 — SNMPv3 `device_identity` (implemented)

When **`snmpv3.device_identity@1.0.0`** is selected and the job credential profile transport is **`snmpv3`**, **`daemon/cred_check_snmp_identity.py`** issues **one SNMPv3 GET** for exactly three OIDs — **`1.3.6.1.2.1.1.1.0`** (sysDescr), **`1.3.6.1.2.1.1.2.0`** (sysObjectID), **`1.3.6.1.2.1.1.5.0`** (sysName). **No walk**, **no SET**, **no operator-supplied OIDs**. Requires **`pysnmp`** on the worker host (same venv as **`daemon/cred_transport_snmp.py`** handshake). Auth/priv protocols match slice 5 handshake (**MD5/SHA** auth; **AES/AES128/DES** privacy); **`invalid_profile`** when privacy without auth, unsupported protocol strings, or contradictory **`security_level`**.

**Results:** **`normalized_json`** contains **`snmpv3_identity`** (bounded strings), **`normalized_identity`** (**name** / **vendor_hint** / **model_hint** heuristics), **`source`**, **`partial`**. Status **`success`** (all three values), **`partial`** (one or two values), or **`failed`** (SNMP/auth/timeout errors, or **`partial_result`** when the GET succeeds but **no** usable OID values). **`metrics_json`** may include **`oids_present`**. Optional artifact **`snmp_identity_json`** holds OID values only (**≤4 KiB**), not packet captures.

**Observations (summarized):** **`hostname_observed`** / **`fqdn_observed`** from **sysName** when present; **`device_identity_observed`** digest — **no** per-OID explosion. **No** device merge, **no** assertion writes from the executor.

**Run-detail API:** **`st_cc_normalized_preview_public`** exposes short previews (**packages_sample** for package inventory; **display_preview** / **normalized_os** for os_release; SNMP field previews) — not full **`normalized_json`**. **`summary_public`** strips internal worker fields (`slice`, `executor`, empty placeholder noise) and includes **`inventory_diff_packages_*`** rollups when present. **`observations_summary`** groups observation types with counts and lists **`software_inventory_snapshots`** (per-target diff summary fields — no per-package dump).

**No-network test:** `python3 daemon/cred_check_snmp_identity_selftest.py`.

---

## 7. Trusted data integration

Checks **write observations** (and optionally **findings**) through a **single ingestion path**, analogous to scanner/Zabbix write paths described in [Trusted data model](TRUSTED_DATA_MODEL.md).

**Slice 10 (implemented):** `api/lib_reconciliation.php` lazy reconciliation **consumes** persisted **`os_version_observed`**, applies **freshness (90d TTL)** vs scan/Zabbix, and tunes **`canonical_hostname`** scoring so SNMP **`sysName`** supports identity **without** pretending multi-source corroboration when only SNMP shaped both FQDN + short label. **`device_identity_observed`** is attached as an assertion-source **context** row only. **`package_inventory_observed`** stays **summary evidence** — **no CVE / findings**. **`software_inventory_snapshot_observed`** + normalized **`software_inventory*`** state feed **slice 2** **`software_inventory_summary`** (single summary assertion per asset, **not** per-package). Workers still **never** write **`asset_assertions`** directly.

| Check output | Observation / evidence | Assertion impact |
|--------------|------------------------|------------------|
| Installed package list | Slice 8: summarized **`package_inventory_observed`** + **normalized `software_inventory*`** durable state + **`software_inventory_snapshot_observed`** diff summary; legacy **`software_observed`** cleaned up; per-package SBOM **deferred** | Slice 2: **`software_inventory_summary`** summary assertion only (PHP lazy reconcile). **No** CVE/software vulnerability assertions — deferred to future correlation work — **not** direct SQL from the worker. |
| SNMP sysName / identity | Slice 9: **`hostname_observed`** / **`fqdn_observed`** + **`device_identity_observed`** summary only | Lazy **`canonical_hostname`** reconciliation (slice 10 tuning); **no** auto-merge or executor-direct **`canonical_hostname`** writes. |
| `/etc/os-release` | `os_version_observed` | Lazy **`os_platform`** reconciliation (slice 10): authenticated release preferred when fresh; agreement/conflict explanations; stale release does not dominate. |
| Missing patch detector | `patch_state_observed` or **finding** row with CVE/KB link | Findings are triage objects; optional later assertion types for “patch posture” if introduced with schema. |
| Local service list | `service_list_observed` (bounded) | Informational / future “exposed service” assertions with strict reconciliation. |
| Config drift | `config_finding` + artifact hash | Assertions only if product defines `config_assertion` slice later. |

**Rules**

- Plugins produce **normalized_json**; ingester maps to `asset_observations` with `source_id` = recon source **`credentialed_check`** (seeded in `recon_sources`) and `source_object_ref` = e.g. `run:{run_id}:target:{target_row_id}:ssh.linux.os_release@1.0.0`.
- **Never** overwrite `asset_assertions` inside the check executor. Reconciliation runs append to `reconciliation_runs` and update assertions using existing patterns (lazy or batch).
- **Low-confidence** or conflicting observations remain visible in evidence UI; **trusted_*** style promotion stays governed by [Trusted data model](TRUSTED_DATA_MODEL.md) thresholds.

---

## 8. Operator workflow (UI)

1. **Define credential profile** — Transport, principal, secret entry (once), scope binding; save.
2. **Test credential** — Run handshake-only test; show pass/fail and **safe** error class (no secret echo).
3. **Assign scope/assets** — Choose inventory scope, tag, or explicit asset list; confirm overlap with profile allowlist.
4. **Select checks** — Pick plugins (version pinned); show privilege and data sensitivity summary.
5. **Preview execution** — Target count, estimated duration band, concurrency; confirm RBAC and maintenance window note (informational).
6. **Run** — Queue run; show live status per target; allow **cancel** (best-effort stop on worker).
7. **Review results** — Per asset: normalized summary, downloadable artifacts (redacted), link to new observations/findings.
8. **Apply/accept** — Where product supports it: accept finding risk, or trigger existing remediation **tickets** (human), not auto-remediation.

---

## 9. Safety controls

- **Concurrency limits:** global and per-job max parallel targets; per-subnet optional throttle.
- **Command allowlists:** MVP plugins = fixed argv; no operator-injected shell.
- **Sandboxing:** worker processes as low-privilege OS user; separate temp dir; no network egress from worker except to declared targets (optional future hardening).
- **Per-check timeout:** manifest default + job cap.
- **Output size caps:** stdout/stderr and JSON normalized size; reject with `policy_output_too_large`.
- **Retry policy:** idempotent transports only; max N retries with backoff; no retry on auth failure.
- **Cancellation:** cooperative — stop scheduling new targets; signal running SSH/WinRM sessions.
- **Rate limits:** per credential profile and per IP (SNMP especially).
- **Safe logging:** log `run_id`, `asset_id`, `plugin_key`, status codes; **never** log env vars or command lines containing secrets.
- **Failure isolation:** one target failure does not abort entire run unless policy `fail_fast` (default off).

---

## 10. Audit and accountability

Audit events (append-only table or existing audit stream extension):

| Event | Payload hints |
|-------|----------------|
| `credential.created` / `updated` / `deleted` | profile id, actor, transport type |
| `credential.test` | profile id, success/fail, error class |
| `check.job.created` / `updated` / `disabled` | job id, plugin list hash |
| `check.run.started` / `completed` / `failed` / `cancelled` | run id, job id, counts |
| `check.target.finished` | run id, asset id, status |
| `plugin.enabled` / `disabled` | plugin_key, version, actor |
| `finding.generated` / `resolved` | finding id, link to result id |
| `evidence.accepted` | operator ack of artifact or normalized row |

---

## 11. Reporting and exports

- **Host details (MVP slice 11):** Overview tab includes a compact **Credentialed checks** block when the schema is present and there is activity or inventory summaries: last target completion with plugins executed, latest target/run state, **summarized** package inventory (manager, count, `partial` / `truncated` flags — not the full package table), SNMP identity summary when present, optional OS/trust note when the reconciliation explanation references authenticated evidence, and a disclosure list of recent runs. Admins get a shortcut to **Settings → Credentialed checks — jobs & runs**.
- **Settings runs table:** Filterable list (`status`, profile transport, `profile_id`, plugin substring), per-row duration, target completion counts, partial/result-failure badges, worker job id. **Run detail** groups targets, bounded normalized previews (optional **View details** for capped os_release JSON), **`observations_summary`** (counts + **`software_inventory_snapshots`** table — no giant per-package observation list), artifact metadata (kind/size/sha256 only — no blob), operator **`summary_public`**, raw `summary_json` still present for compatibility, and an **admin-only** `worker_jobs` debug panel when `GET …&debug=1` is used.
- **System health:** `credential_check_runs` snapshot adds partial-result counts (24h), average completed duration (24h), stale active runs (\>3h), enabled jobs on disabled/archived profiles, approximate result/artifact row counts, and `warning_hints` — extra lines stay muted until something is wrong (or admin store hint when anomalies fire).
- **Trusted data / evidence UI:** Observation and assertion-source rows show a subtle **source tier** chip (`Auth` = credentialed, `Scan` = unauthenticated scan, `Mon` = monitoring inventory, `Enrich` = enrichment) derived from `recon_sources.source_type` — not a security label, for operator context only.
- **Retention messaging:** UI copy states that previews and stored rows are **bounded** and retention is **operational** (no automatic pruning in this release unless aligned with a future cleanup job).
- **Reports / exports / change alerts:** Job-scoped coverage, delta package exports, and diff alerts remain **deferred** beyond summarized host and run surfaces.

---

## 12. MVP proposal

**Ship first**

1. **SSH — Linux package inventory** — `dpkg`/`rpm` query via **fixed** read-only commands; output → `package_installed` observations.
2. **SSH — local OS release** — Read `/etc/os-release` allowlisted path only → `os_version_observed` feeding existing OS reconciliation path conceptually.
3. **Optional SNMPv3 — device identity** — `sysDescr`, `sysObjectID`, `sysName` only → observations for identity/context (not replacing canonical hostname logic without reconciliation).

**Explicitly avoid in MVP**

- Arbitrary command execution or user-supplied scripts.
- Broad “use this one root key everywhere” without per-profile scoping UI enforcement.
- Auto-remediation.
- Windows-first WinRM if timeline is tight: keep WinRM in **design** and transport table, ship **SSH + SNMP** first.

---

## 13. Deferred work

- Auto-remediation and patch push.
- Arbitrary script execution or “bring your own command”.
- Full plugin marketplace / unsigned third-party plugins.
- Complex enterprise vault integration (CyberArk, Vault, cloud KMS) — start with app-level encryption only.
- Large compliance frameworks (full CIS benchmark automation) as a single product switch.
- Replacing dedicated vulnerability scanners — credentialed checks **augment** evidence, not clone Tenable/Qualys scope.

---

## 14. Open questions

1. **Worker placement:** Same host as SurveyTrace PHP app vs dedicated worker container — impacts secrets, concurrency, and cancellation.
2. **SSH host key TOFU vs inventory:** Require pre-imported host keys vs first-run confirmation workflow.
3. **Multi-hop Windows:** Explicitly unsupported vs long-term Kerberos delegation model.
4. **Finding vs observation-only:** Which package/CVE gaps create **findings** immediately vs observation-only until correlation exists?
5. **Device vs asset target:** When job targets a device, how to pick **management IP** if multiple assets exist — operator rule vs automatic?
6. **SNMP write:** Permanently disallow vs future controlled SET with separate RBAC tier.
7. **Retention:** Artifact retention vs cost; legal hold vs TTL.
8. **Encryption key rotation:** How to re-wrap `secret_ciphertext` without downtime.
9. **Plugin signing:** Internal only vs future third-party signature requirement.
10. **Integration with scan jobs:** Same UI as “rescan” or separate “cred check” queue to avoid operator confusion.

---

## References

- [Roadmap — Credentialed checks engine](../ROADMAP.md#credentialed-checks-engine)
- [Roadmap — Design approach](../ROADMAP.md#design-approach) (explicit workflows, separation of concerns)
- [Trusted data model](TRUSTED_DATA_MODEL.md) (observations, assertions, evidence, operational display)
