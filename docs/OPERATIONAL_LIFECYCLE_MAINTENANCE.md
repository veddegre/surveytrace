# Operational Lifecycle and Maintenance Plan

This plan covers the next hardening milestone focused on long-term operational survivability before expanding capability scope.

## Goals

- Keep credentialed checks and worker-backed operations maintainable over long runtimes.
- Give operators safe, explicit tools for lifecycle maintenance.
- Improve recoverability for common operational failure modes (stuck leases, growth pressure, key/encryption drift).
- Add visibility and runbook-level guidance without introducing new execution capability.

## Scope

- Manual credential secret rewrap/rotation utility (admin/operator initiated).
- Manual retention and prune helpers for high-growth tables.
- Manual stale lease / stuck worker recovery helpers.
- Admin maintenance visibility polish in existing settings/health surfaces.
- Backup/restore and deployment runbook improvements with validation checks.

## Non-goals

- No new credentialed check transports.
- No CVE fusion, remediation, findings expansion, or package-vuln matching.
- No automatic background pruning daemons.
- No SQLite replacement.
- No systemd replacement.
- No UI redesign.
- No Vault/KMS implementation in this milestone.

## Risks Addressed

- Legacy secret envelopes lacking current context binding metadata.
- Growing operational tables without first-class maintenance workflows.
- Stuck worker jobs/runs after worker crashes or lease drift.
- Operator uncertainty around what can be safely cleaned or recovered.
- Restore/deploy drift around encryption key handling and maintenance sequence.

## Proposed Slices

1. **Credential secret rewrap / rotation utility**
   - Manual dry-run/apply utility to rewrap legacy envelopes with current key/context.
2. **Manual retention/prune tooling**
   - Admin scripts/endpoints for bounded cleanup of high-growth tables.
   - Slice 2 implementation: `scripts/prune_operational_history.php` + `scripts/st_operational_prune_selftest.php` (CLI-first, dry-run default, no scheduler).
3. **Stale lease / stuck worker recovery helper**
   - Safe, explicit tooling to reconcile stale `worker_jobs` and linked run states.
   - Slice 3 implementation: `scripts/recover_stale_worker_jobs.php` + `scripts/st_stale_worker_recovery_selftest.php` (manual dry-run/apply, no auto-sweeper).
4. **Admin maintenance visibility polish**
   - Surface maintenance-relevant counts/hints in existing admin health/settings surfaces.
5. **Backup/restore validation docs and checks**
   - Add concrete runbooks and validation checklists for restore/deploy/key lifecycle.
   - Slice 5 implementation: `scripts/validate_backup_restore_readiness.php` (read-only readiness checks, no secret output, no DB mutation).

## Tables Affected

- `credential_profiles` (`secret_ciphertext`, `updated_at`)
- `user_audit_log` (maintenance/re-wrap audit entries)
- Future slices:
  - `credential_check_results`
  - `credential_check_artifacts`
  - `worker_job_events`
  - `worker_job_attempts`
  - `worker_jobs`
  - `credential_check_runs`
  - `reconciliation_runs`

## APIs / Tools Likely Needed

- CLI-first maintenance scripts under `scripts/` for operational safety.
- Optional admin-only API actions (CSRF protected) only when low-risk and additive.
- Existing secret envelope helpers in `api/lib_secrets.php`.
- Existing worker/credential helpers in `api/lib_worker_jobs.php` and `api/lib_credential_check_ops.php`.

## UI Surfaces Likely Affected

- Settings admin sections for maintenance actions/status.
- System Health (`worker` + `credential_check_runs`) for maintenance hints.
- Optional compact admin-only maintenance status block (no layout redesign).

## Validation Strategy

- Syntax: `php -l` touched PHP, `python3 -m py_compile` touched Python, `bash -n` touched shell.
- Slice-specific no-network selftests where feasible.
- Dry-run/apply tests against temp SQLite fixtures for maintenance scripts.
- Safety checks: no plaintext secret leakage to output/log/audit payloads.
- Regression checks for existing credential profile CRUD/test and worker paths.

## Slice 2 Retention Policy (Current)

- **Default (no `--include-runs`):**
  - `worker_job_events`
  - `worker_job_attempts` (old + terminal/missing parent only)
  - `credential_check_artifacts` (old + terminal/missing run context)
  - `credential_check_results` (old + terminal/missing run context)
  - `reconciliation_runs`
- **With `--include-runs`:**
  - Adds terminal-tree pruning for old `credential_check_runs` / `credential_check_run_targets` and old terminal `worker_jobs` with child rows deleted first.
- **Never pruned by this tool:** inventory/assertion/scan/finding/core asset tables.

## Slice 3 Recovery Policy (Current)

- Detect stale worker jobs in `leased` / `running` / `retrying` older than threshold.
- Finalize queued jobs with stale `cancel_requested_at`.
- Finalize stale running attempts when parent is stale/terminal.
- Optional `--run-sync` aligns stuck credential-check runs to terminal worker-job state.
- Default job type filter is `credentialed_check` (collector ingest excluded unless explicit).
- No deletes, no automatic retries, no automatic scheduler.

## Routine Monthly Checklist

1. Take a DB backup.
2. Dry-run secret rewrap check:
   - `php scripts/rewrap_credential_secrets.php`
3. Dry-run retention check:
   - `php scripts/prune_operational_history.php --older-than-days=90`
4. Dry-run stale recovery check:
   - `php scripts/recover_stale_worker_jobs.php --older-than-minutes=60 --run-sync`
5. Review System Health maintenance hints and row-growth signals.
6. Apply only the needed tool(s) during a maintenance window.

## Pre-release Maintenance Checklist

1. Confirm no unexpected rewrap candidates remain (or document accepted debt).
2. Confirm stale worker candidate count is zero or acknowledged.
3. Run retention dry-run and capture projected delete counts.
4. Run relevant selftests (`st_cred_secret_rewrap_selftest.php`, `st_operational_prune_selftest.php`, `st_stale_worker_recovery_selftest.php`).
5. Record maintenance actions in release notes/runbook if `--apply` was used.

## Tool Boundaries (What They Never Touch)

- `rewrap_credential_secrets.php`
  - Never exposes plaintext secret values.
  - Never modifies non-secret profile metadata semantics.
- `prune_operational_history.php`
  - Never prunes asset/inventory/assertion/scan/finding core tables.
  - Never touches active running/queued worker/run state by default.
- `recover_stale_worker_jobs.php`
  - Never deletes rows.
  - Never retries remote credentialed execution automatically.
  - Never touches collector ingest substrate unless explicitly requested via `--job-type`.

## Backup Checklist (Manual)

Required backup set before maintenance or upgrade:

1. SQLite DB file (`data/surveytrace.db` and active WAL/SHM sidecars when present).
2. Environment file holding `SURVEYTRACE_CRED_SECRET_KEY` (for example `/etc/surveytrace/surveytrace.env`).
3. Systemd unit/env overrides used in production.
4. Any local custom docs/config tracked outside git.
5. Release metadata context (`VERSION`, deployment notes/changelog snippets used by your process).

## Restore Checklist (Manual)

Recommended order:

1. Stop SurveyTrace services.
2. Restore DB and environment/config files together.
3. Verify `SURVEYTRACE_CRED_SECRET_KEY` is present and matches pre-backup value.
4. Run readiness validation:
   - `php scripts/validate_backup_restore_readiness.php`
5. Start services.
6. Check System Health and credentialed-check run visibility.
7. Run maintenance dry-runs as needed:
   - `php scripts/rewrap_credential_secrets.php`
   - `php scripts/prune_operational_history.php --older-than-days=90`
   - `php scripts/recover_stale_worker_jobs.php --older-than-minutes=60 --run-sync`

## Key-Loss / Multi-node Warnings

- Restoring DB without the original `SURVEYTRACE_CRED_SECRET_KEY` preserves profile metadata but breaks secret decrypt for stored credential profiles.
- Web/API and worker nodes must share the same key material for credentialed checks to succeed.
- There is no Vault/KMS fallback in this milestone.

## Deferred Automation

- Automated key rotation/re-wrap jobs.
- Automatic retention schedulers.
- Automatic stale lease sweep daemons.
- Vault/KMS provider integration and dual-key migration workflows.
