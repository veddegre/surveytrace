# Credential secret security model

SurveyTrace stores **credential profile secrets** encrypted at rest. The web tier (PHP-FPM / Apache) **does not** hold the symmetric key used to encrypt or decrypt those envelopes. Operators and auditors should treat this document as the canonical description of that boundary, how the **sudo helper** (`daemon/cred_secret_ops_cli.php`) fits in, and what **must never** be done in production.

---

## Goals and threat model (bounded)

- **At rest**: Secrets are stored only as ciphertext envelopes bound to a profile id and algorithm metadata (see `api/lib_secrets.php` and related schema). Plaintext secrets are not written to SQLite for profiles.
- **In motion (API/UI)**: List, detail, and transport-test responses expose **public** profile rows only (no ciphertext, nonce, tags, PEM, or password fields). Regression coverage lives in `scripts/st_credential_secret_no_leak_selftest.php`.
- **In use (workers)**: Credentialed-check workers decrypt on the host that runs Python (`daemon/cred_check_run.py`) via `daemon/cred_decrypt_cli.php` / install-local PHP, using the same key material as the **`surveytrace`** UNIX account’s environment—not the FPM pool user.
- **Out of scope (explicitly)**: Vault/KMS, automatic rotation, new transports, and “secure RAM” guarantees beyond what PHP and Python realistically provide.

---

## Architecture: who holds the key

| Component | Key in env? | Role |
|-----------|-------------|------|
| **`surveytrace` user** (`/etc/surveytrace/surveytrace.env`) | **Yes** (when configured) | Source of truth for `SURVEYTRACE_CRED_SECRET_KEY` (or successor env names per install docs). Used by CLI maintenance, backup tooling, and **`cred_secret_ops_cli.php`** when invoked **as** `surveytrace`. |
| **php-fpm pool (`www-data`, `apache`, …)** | **No** (when helper path is used) | Serves UI/API; calls `st_cred_secret_*` helpers that **`sudo` → `surveytrace` → `cred_secret_ops_cli.php`** for encrypt/decrypt/status. |
| **Credential-check worker host** | **Yes** (same key value) | Workers must decrypt envelopes locally; key parity across encrypting master and executing workers is a **restore/DR** requirement. |

**Why FPM does not own the key:** If the pool process could read the key file or env, any RCE or accidental `phpinfo()`-style disclosure in the web stack could expose the material that decrypts **all** profile secrets. Splitting key access to a dedicated OS identity (`surveytrace`) plus tight **sudoers** reduces blast radius: only the listed PHP CLI binary and script path may run as that user, without a password.

Reference implementation: `api/lib_cred_secret_helper.php` (web → sudo → helper), `daemon/cred_secret_ops_cli.php` (encrypt/decrypt/status JSON on stdin).

---

## Environment file permissions

Typical production layout:

- `/etc/surveytrace/surveytrace.env` is readable by **`surveytrace`** (root-owned, mode `0640` or tighter, group `surveytrace`).
- The **FPM pool user must not** be able to read this file. Release validation includes proving `www-data` (or your pool user) gets **denied** read while `surveytrace` succeeds.

If the pool user could read the env file, the web tier could bypass the helper and read the key directly—defeating the model.

---

## Sudo helper flow (summary)

1. Admin action in UI hits PHP code that needs envelope ops (save profile secret, transport handshake, etc.).
2. PHP builds a **small JSON** command for `cred_secret_ops_cli.php` (action + payload), never logging the full stdin.
3. `proc_open` runs: `sudo -n -u surveytrace -- $PHP_CLI $INSTALL/daemon/cred_secret_ops_cli.php` with the JSON on stdin (see `lib_cred_secret_helper.php` for exact argv and diagnostics).
4. Helper loads env as `surveytrace`, runs libsodium (or configured stack), returns **JSON** to stdout. Errors use **tokenized** messages safe for logs.

**sudoers** must allow exactly: pool user → `surveytrace` → fixed PHP binary + fixed script path, **NOPASSWD**. Templates ship in setup/deploy; adjust pool user name per distro (Debian: `www-data`, RHEL family: often `apache`).

Parity selftest: `scripts/st_cred_secret_helper_web_parity_selftest.php` (requires sudoers on the host). The aggregated `scripts/release_security_gate.php` skips this unless you pass **`--require-helper-parity`**.

---

## Backup and restore implications

- **Backups** include ciphertext envelopes in the DB dump; they do **not** include plaintext secrets.
- **Restores** on a new node are useless for decrypt unless the **same** `SURVEYTRACE_CRED_SECRET_KEY` (and algorithm compatibility) exists on that node for both the **web encrypt path** and **worker decrypt path**.
- Document key custody outside SurveyTrace (password manager, offline seal, HSM export procedure—whatever your org uses). SurveyTrace does not rotate keys automatically.

Rewrap utility (key change with old+new key available): `scripts/rewrap_credential_secrets.php` plus selftest `scripts/st_cred_secret_rewrap_selftest.php`.

---

## Credentialed job scheduler (`credential_schedule_tick.php`)

The **`surveytrace-scheduler`** loop may invoke **`scripts/credential_schedule_tick.php`**, which uses the **same** `st_cc_run_launch()` / `worker_jobs` path as the UI. The tick **does not** read or decrypt credential envelopes, does not shell out to system cron, and does not execute arbitrary host commands. It only reads job templates, writes schedule metadata and **`user_audit_log`** rows (actor `system`), and enqueues work the existing **`surveytrace-credential-check-worker`** consumes. Operators should still treat scheduled launches as **automated use of stored credentials** within the same trust boundary as manual “Run now”.

## Audit model (credential use)

Safe, operator-facing audit actions (details are JSON in `user_audit_log.details_json`):

| Action | When | Typical fields (no secret material) |
|--------|------|--------------------------------------|
| `credential_profile.secret_tested` | After admin transport handshake | `credential_profile_id`, `transport`, `target_host`, `plugin_key` (`credential_profile.transport_test`), `result_code`, `duration_ms` |
| `credential_profile.secret_used` | After successful decrypt of a non-empty envelope at run start | `credential_profile_id`, `credential_check_run_id`, `target_row_id`, `asset_id`, `transport`, `target_ip`, `plugins_scheduled`, `result_code` (`decrypt_ok`) |
| `credential_profile.secret_auth_failed` | SSH/SNMP path returns `auth_failed` | Profile/run/target ids, `transport`, `target_ip`, `plugin_key`, `result_code` |

**Never logged in these events:** usernames/passwords/tokens, PEM blocks, decrypted JSON, or raw stderr from remote systems.

Additional handshake outcomes may still emit `credential_profile.test_succeeded` / `test_failed` (see `api/lib_credential_profile_transport_test.php`).

---

## Retention and pruning

High-churn tables:

- `worker_job_events` — per-attempt diagnostics.
- `credential_check_results` / `credential_check_artifacts` — plugin output and bounded stdout blobs.
- `user_audit_log` — security-relevant history (treat as **append-only** for compliance; optional maintenance rows only).

**Operational scripts:**

- Broad operational prune: `scripts/prune_operational_history.php` (guarded; can include runs).
- **Credential-runtime-focused** prune (artifacts → results → run rows → terminal jobs; preserves recent runs and audit trail except deleted run-scoped rows): `scripts/prune_credential_runtime_history.php` — **dry-run by default**; `--apply` writes `maintenance.prune_credential_runtime_history` to `user_audit_log` when the table exists.

`scripts/security_runtime_audit.php` warns when runtime tables exceed row thresholds and when no credential-runtime prune audit has appeared recently (see script for thresholds).

---

## Operational checks (release and ongoing)

Automated (from repo root on a build tree):

- `php scripts/check_deploy_coverage.php .`
- `php scripts/st_credential_secret_no_leak_selftest.php`
- `php scripts/security_runtime_audit.php --install-root=/opt/surveytrace` (use **`--strict`** in CI if WARN must fail)
- `php scripts/release_security_gate.php` (optional `--require-helper-parity` on a configured host)

Manual (production):

- Browser **Network** tab: credential profile APIs must not show ciphertext, PEM, or password assignments.
- Wrong-password handshake: safe error surface only.
- Run detail / timeline: no secret-shaped strings.

---

## What admins must **never** do

- **Do not** inject `SURVEYTRACE_CRED_SECRET_KEY` (or equivalent) into **Apache / php-fpm** pool environment “to make it easier.” That collapses the trust boundary.
- **Do not** chmod `surveytrace.env` world-readable or add the FPM user to the `surveytrace` group unless you fully accept key exposure to the web stack.
- **Do not** paste decrypted secrets into tickets, chat, or audit “notes” fields.
- **Do not** disable `sudo -n` helper without an alternative that keeps the key off the FPM uid.
- **Do not** run `cred_secret_ops_cli.php` as root in production except via the designed `surveytrace` drop-in; avoid ad-hoc copies of the env file under web roots.

---

## Related documentation

- [Credentialed checks vs collectors & scans](credentialed-checks-integration.md) — execution locality and why scans do not auto-run cred jobs.
- [Troubleshooting — Credential secret helper](troubleshooting.md#credential-secret-helper--security-model) (symptoms, visudo checks, probes).
- [Release readiness checklist](../RELEASE_READINESS_CHECKLIST.md) — security gate and host validation rows.
- Engine design: [Credentialed Checks Engine](../CREDENTIALED_CHECKS_ENGINE.md).

---

## Normalized software inventory (API exposure)

Credentialed SSH package inventory persists **normalized** identities in `software_inventory` / `software_inventory_versions` / `software_inventory_asset_state` (worker-side SQLite, same DB as the app). The web tier serves **bounded** reads via `api/software_inventory.php` (prefix match on sanitized names; no `WHERE` clause from raw client SQL). **Health** `trusted_data` counters include row totals and latest `last_seen_at` timestamps only—never raw `dpkg-query` / `rpm -qa` artifact bodies. Full stdout remains in `credential_check_artifacts` for authorized operators, not in default JSON surfaces.

**Local advisory correlation (optional operator import):** `vulnerability_advisories` / `vulnerability_advisory_packages` / `asset_vulnerabilities` are populated from **bounded local JSON** via importer CLIs (`scripts/import_advisories.php`, `scripts/import_nvd_metadata.php`, `scripts/import_distro_advisories.php` — no shell; HTML stripped where applicable). Public APIs (`api/vulnerabilities.php`, additive `vulnerability_inventory` on single-asset `assets.php`) return **allowlisted columns and integer IDs only**—no arbitrary SQL from clients, no raw feed blobs. Correlation runs **offline** (`scripts/run_vulnerability_correlation.php`); the cred worker only **enqueues** a deduped `worker_jobs` hint after inventory success — **no** heavy matching during the SSH session.

**Package authority (trust boundary):** each advisory row carries **`package_authority`**: **`metadata_only`** (NVD-style CVE metadata in `description` / CVSS / optional `references_json`), **`vendor_distro`** (distro vendor package truth such as fixed versions per release), or **`internal`** (operator/sample rules, including explicit package rules merged onto an NVD key). **Correlation joins only `vendor_distro` and `internal`**. Rows that are **NVD metadata-only** do **not** create **`asset_vulnerabilities`** matches by themselves, even if legacy or mistaken package rows exist — vendor/internal rules are required for affected correlation. UI/API wording uses **“Vendor advisory match”**, **“Internal advisory match”**, **“NVD metadata only”**, and **correlation confidence**; do not treat metadata-only rows as proof an installed package is affected.

**Advisory removal (`scripts/remove_advisory.php`):** dry-run by default; **`--apply`** deletes the **`vulnerability_advisories`** row (FK cascades packages and correlated **`asset_vulnerabilities`**, which in turn removes triage/notes/activity for those rows). Without **`--force`**, removal is limited to **test/internal posture** (`internal`, `sample`, **`CVE-TEST-*`**, or **`nvd` + `metadata_only`**). **Vendor/distro** advisories require **`--force`** after explicit review. See [Vulnerability advisory operator runbook](vulnerability-advisory-runbook.md).

**Vulnerability triage API (`api/vulnerability_triage.php`):** allowlisted **GET/POST actions** only; mutations require CSRF and **`scan_editor`/`admin`**. Analyst **notes** are stored as **plain text** with a fixed max length; **never render note or actor strings as HTML** — treat as untrusted text (escape on output). **`vulnerability_activity_log.details_json`** is written only from an **allowlisted key set** (no arbitrary client JSON). Suppression does **not** delete `asset_vulnerabilities` rows. Operational views and list endpoints use **hard caps** on rows returned. Maintenance CLI **`scripts/resync_vulnerability_triage_priority.php`** defaults to **dry-run** (counts only); **`--apply`** mutates **`asset_vulnerability_triage.priority`** only — output is aggregate counts, not advisory bodies or secrets.

---

## Operational integrity (validation model)

SurveyTrace includes a unified **operational integrity framework** (`scripts/run_operational_integrity_suite.php`) that validates end-to-end correctness without mutating state:

- **Read-only by design**: all integrity checks use `PRAGMA query_only=1` and never repair, chmod, restart, or apply fixes automatically.
- **Bounded validation**: every scan/query is capped with LIMIT clauses; no unbounded table scans, no giant dataset loads, no network access.
- **Deterministic ordering**: checks run in a fixed domain order (lint → selftests → deploy → DB → runtime → health → shell syntax) for reproducible results.
- **Graceful degradation**: missing tables, absent files, or partial installs produce INFO/WARN rather than crashing the suite.
- **Failure semantics**: FAIL indicates a definite invariant violation (orphans, duplicate keys, syntax errors); WARN indicates drift requiring operator attention (stale data, expired suppressions); both are actionable but only FAIL blocks release in non-strict mode.
- **Recovery expectations**: the suite diagnoses problems but never fixes them. Remediation is manual or via dedicated CLIs (`recover_stale_worker_jobs.php`, `resync_vulnerability_triage_priority.php --apply`, etc.).
- **No secret exposure**: integrity output contains counts and identifiers only; never raw credentials, advisory bodies, or package lists.

Related scripts: `check_database_integrity.php` (standalone DB validator), `st_operational_integrity_selftest.php` (in-memory regression), `diagnose_operational_integrity.php` (JSON diagnostics).

---

## Limitations (honest)

- PHP and Python do not provide guaranteed zeroization of strings; we **discard references** and avoid logging sensitive structures—**not** cryptographic memory wiping.
- Any host that can run the worker with the key can decrypt envelopes for profiles it can read from the DB—**DB + file access** remain the ultimate gate.
- Third-party libraries and remote commands may still emit sensitive data if misconfigured; timeline redaction and result normalization reduce but cannot mathematically eliminate all leaks without strict allowlists.
