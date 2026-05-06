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

**Credentialed checks** are **authenticated, in-scope collection actions** initiated by operators (or explicitly scheduled jobs they defined). They use stored **credential profiles** and a chosen **transport** (SSH, WinRM, SNMPv3, etc.) to run **bounded plugins** on a **target asset or device**, producing **structured results** and **evidence artifacts** that SurveyTrace normalizes and ties to the trusted data path.

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

---

## 2. Execution model

Definitions:

| Concept | Definition |
|--------|------------|
| **Check job** | A **logical intent**: which targets (assets/devices or scope), which **credential profile** (or ordered fallback list), which **plugins** (and versions), schedule or ad-hoc, and policy knobs (timeouts, concurrency). Persists as a template or one-shot definition. |
| **Target asset/device** | Primary **asset** (`assets.id`, IP/identity) or **device** (logical grouping). Resolution rules: job specifies asset list or scope; executor resolves to concrete endpoints (IPs, management interfaces). |
| **Credential profile** | Named bundle: transport type, principal identity (username, community user, etc.), **secret material by reference** (encrypted blob or external ref in future), scope tags, allowed transports/plugins. Never returned verbatim via API. |
| **Transport** | Mechanism to reach the host: **SSH**, **WinRM**, **SNMPv3** (initial set). Pluggable conceptually; each enforces auth and channel limits. |
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
- **Secret storage:** application-encrypted **blob** in DB or OS-backed secret store **later**; encryption key **outside** SQLite row (env/HSM path deferred).
- **Scoped credentials:** profiles attach to **allowed scope_ids**, **asset tags**, or explicit **asset allowlists**. Deny by default if unset (product choice: “explicit allowlist only” for MVP is safest).
- **Rotation:** operators mark `rotated_at` / `expires_at`; jobs warn on expiry; **no auto-rotation** in MVP.
- **RBAC:** separate permissions, e.g. `credential:read_meta`, `credential:create`, `credential:test`, `check:run`, `check:review`. Viewing **metadata** ≠ using credential in a run (both audited).
- **Audit logging:** every create/update/delete/test/run references `credential_profile_id` (not secret).
- **Never expose secrets:** APIs return `has_password`, `key_fingerprint`, `last_test_status`, never plaintext passwords or private keys. Logs store **result codes** and **redacted** excerpts only.

### Credential test

- **Dedicated** “test” action: minimal handshake (e.g. SSH `echo` / WinRM ping / SNMP GET sysDescr.0) with **short timeout**, **no plugin side effects**, audit event `credential.test`.

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

### `credential_check_results`

| Column | Notes |
|--------|------|
| `id` | PK |
| `run_id`, `asset_id`, `plugin_key`, `plugin_version` | |
| `status` | success / partial / failed |
| `normalized_json` | Schema-validated output |
| `metrics_json` | duration, bytes, retry count |

### `credential_check_artifacts`

| Column | Notes |
|--------|------|
| `id` | PK |
| `result_id` | FK |
| `kind` | stdout / stderr / snmp_capture / file_excerpt |
| `storage_path` or `blob` | Prefer file path for large payloads |
| `sha256`, `size_bytes` | |
| `redaction_version` | |

Indexes: `(run_id)`, `(asset_id, started_at)` for host history; `(job_id, started_at)` for job audit.

---

## 7. Trusted data integration

Checks **write observations** (and optionally **findings**) through a **single ingestion path**, analogous to scanner/Zabbix write paths described in [Trusted data model](TRUSTED_DATA_MODEL.md).

| Check output | Observation / evidence | Assertion impact |
|--------------|------------------------|------------------|
| Installed package list | New/updated `observation_type` e.g. `package_installed` with normalized `(name, version, arch)` | May inform future **software inventory** assertions — **only** via reconciliation slice, not direct SQL update to `asset_assertions`. |
| `/etc/os-release` | `os_version_observed` / strengthens `os_fingerprint_*` family | Feeds existing **`os_platform`** reconciliation; may raise confidence or conflict for operator review. |
| Missing patch detector | `patch_state_observed` or **finding** row with CVE/KB link | Findings are triage objects; optional later assertion types for “patch posture” if introduced with schema. |
| Local service list | `service_list_observed` (bounded) | Informational / future “exposed service” assertions with strict reconciliation. |
| Config drift | `config_finding` + artifact hash | Assertions only if product defines `config_assertion` slice later. |

**Rules**

- Plugins produce **normalized_json**; ingester maps to `asset_observations` with `source_id` = dedicated recon source, e.g. `surveytrace_credentialed_check`, and `source_object_ref` = `run_id:plugin_key:target`.
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

- **Host details:** New section “Credentialed checks” — last run time, plugin summary, link to artifacts (RBAC), conflicts vs scan/Zabbix called out.
- **Reports:** Job-scoped or inventory-scoped reports include **check coverage** (% assets with successful run in window) and **delta** package lists between runs.
- **Exports:** CSV/JSON columns additive: `last_cred_check_at`, `cred_check_plugins_ok`, optional package hash summary — **no secrets**.
- **Change alerts:** Diff normalized package sets or OS string between runs; tie to existing alert stream patterns.
- **Trusted data diagnostics:** Extend health-style snapshot with counts: runs 24h, failures by `error_code`, observation rows from credentialed source — mirrors “quiet when healthy” philosophy from current trusted diagnostics.

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
