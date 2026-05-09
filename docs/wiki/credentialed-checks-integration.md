# Credentialed checks — integration with collectors, scans, and schedules

This page describes **how credentialed checks fit into SurveyTrace today** versus **network scans**, **remote collectors**, and **scheduled scans**. It complements [Credentialed Checks Engine](../CREDENTIALED_CHECKS_ENGINE.md) (design) and [Credentialed Checks MVP plan](../CREDENTIALED_CHECKS_MVP_PLAN.md) (implementation slices).

---

## Where execution happens

| Component | Credentialed checks? |
|-----------|---------------------|
| **Master node** (`surveytrace-credential-check-worker.service`) | **Yes.** Jobs enqueue `worker_jobs` with `job_type=credentialed_check`; the worker runs `daemon/credential_check_worker.py` / `daemon/cred_check_run.py` against targets resolved on the master (SSH/SNMP from the master’s network perspective). |
| **Collectors** (remote scan workers / `surveytrace-collector` family) | **No.** Collectors run **unauthenticated (or limited) network scans** and related tasks they are assigned. They do **not** load credential profiles, decrypt envelopes, or execute the credentialed-check plugin pipeline. |
| **Scanner daemon** (`surveytrace-daemon`) | **No** automatic credentialed execution. Normal scan launches choose coverage, rates, and scope; they do **not** attach credential profiles or credentialed jobs. |
| **Scheduler** (`surveytrace-scheduler`) | **No** automatic credentialed execution. Scheduled scans repeat the same scan-oriented configuration; they do **not** enqueue credentialed check jobs unless you do so explicitly elsewhere (future product work). |

---

## Operator workflow today

1. **Settings → Credentialed Checks:** define **credential profiles** (metadata + encrypted secrets via the helper), optional **transport handshake** tests, and **check jobs** (profile + plugins + targets).
2. **Run now** on a job enqueues work for the **credential-check worker** on the **master** — not for collectors.
3. **Inventory / observations** produced by credentialed plugins feed the same **trusted data** paths as documented in the engine; that is independent of whether a host was last seen by a collector scan or a routed scan.

---

## Scans and scheduled scans

- **Regular scans** (UI or API) and **scheduled scans** run **network discovery / fingerprinting** (and related logic) per job configuration. They **do not** currently:
  - select a credential profile,
  - auto-start a credentialed check job, or
  - merge credentialed targets with scan scope without a separate explicit action.

- **Future integration** (see [Roadmap — Credentialed checks engine](../ROADMAP.md#credentialed-checks-engine)) must be **explicit opt-in**: e.g. optional profile on a scan or schedule, scope-compatible target filtering, and a clear run mode so **credentialed checks never run silently** as a side effect of “start scan”.

---

## Run history and retention

Credentialed runs create rows in `credential_check_runs`, `credential_check_results`, `credential_check_artifacts`, and related `worker_job_events`. These grow with use.

- **Narrow cleanup (credentialed runtime only):** `scripts/prune_credential_runtime_history.php` — default is **dry-run**; use `--apply` after review. Preserves the newest runs (`--keep-runs`), does not delete **non-terminal** runs or jobs, and only prunes **terminal** runs older than `--days`. See script header for exact policy.
- **Broader operational history:** `scripts/prune_operational_history.php` (optional `--include-runs` for larger trees). Read [Deployment — maintenance](deployment.md#manual-operational-prune-utility-slice-2) and the [Security model — retention](security_model.md#retention-and-pruning).

Always **back up the database** before `--apply` on any prune script.

---

## Summary

| Question | Answer |
|----------|--------|
| Do collectors run credentialed checks? | **No** (not in this release). |
| Where do credentialed checks run? | **Master** — credential-check worker service. |
| Do scans / schedules auto-run credentialed jobs? | **No** — use Settings → Credentialed Checks explicitly. |
| Will future scan linking be silent? | **No** — design requires explicit operator choice (see Roadmap). |
