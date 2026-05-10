# Release readiness checklist

Use this checklist before tagging a **maintenance / stabilization** release. It is **operator- and QA-oriented**: confirm behavior, not new feature work.

**Related:** [CHANGELOG.md](../CHANGELOG.md) · [RELEASE_NOTES.md](../RELEASE_NOTES.md) · [Trusted data model](TRUSTED_DATA_MODEL.md)

---

## A. Install / deploy

| Step | Verify |
|------|--------|
| Fresh **master** install | `sudo bash setup.sh` (or `SURVEYTRACE_SETUP=master`) completes; post-install validation passes. |
| **deploy.sh** on existing master | Completes; post-deploy checks **PASS**; **`check_deploy_coverage.php`** ran clean from the repo before copy; **`release_security_gate.php --static-only`** runs after **`php -l`** (host-neutral selftests); shipped trees match **`scripts/deploy_file_manifest.php`**. |
| Required files present | `api/lib_reconciliation.php`, `api/recon_diagnostics.php`, `daemon/recon_observations.py`, `daemon/st_software_observation_selftest.py`, maintenance CLIs + selftests under **`/opt/surveytrace/scripts/`** (see manifest), `scripts/st_software_inventory_summary_selftest.php`, `scripts/st_software_inventory_evidence_selftest.php`, `scripts/st_software_inventory_diagnostics_selftest.php`, `scripts/st_vulnerability_correlation_selftest.php`, `scripts/st_vulnerability_triage_selftest.php`, `docs/TRUSTED_DATA_MODEL.md` (and cred-checks design docs if shipped) under `/opt/surveytrace`. |
| Manifest drift guard | From a checkout: `php scripts/check_deploy_coverage.php` exits **0** after edits that add `api/*.php`, `daemon/*.py`, or `scripts/*.php`. |
| Stale deploy tree (optional) | After upgrades that rename/remove shipped files: **`sudo bash deploy.sh --cleanup-stale`** (dry-run from a fresh **`git pull`**); review output, backup, then **`sudo bash deploy.sh --cleanup-stale --apply`**. The underlying **`scripts/cleanup_deployed_stale_files.php`** never deletes **`data/`**, **`backups/`**, **`venv/`**, **`.git/`**, SQLite **`.db-wal` / `.db-shm`**, **`.env`**, **`surveytrace.env`**, or log trees (heuristic). Not a substitute for DB/history pruning (`prune_operational_history.php`). Known renames (e.g. `cred_check_slice7_selftest.py` → `cred_check_os_release_selftest.py`) are listed in **`st_cleanup_known_renamed()`** inside that script — run dry-run after helper/manifest changes to confirm no unexpected leftovers. |
| Permissions | `api/`: `surveytrace:www-data`, dirs `2750`, files `640`; `data/`: `2770` / `660` on DB; `daemon/`: `surveytrace:surveytrace`. |
| PHP syntax | `php -l` on changed API files (or run deploy output which includes reconciliation API checks). |
| Python syntax | `python3 -m py_compile daemon/recon_observations.py` (and deploy validates after copy). Include **`daemon/st_software_observation_selftest.py`** when present (`setup.sh` / `deploy.sh` **`py_compile`** loops). |
| systemd | `surveytrace-daemon`, `surveytrace-scheduler`, `surveytrace-collector-ingest` **active** (master). |
| systemd sandbox / SQLite | Installed units for master daemons that open the DB include **`ReadWritePaths`** for the SurveyTrace **`data`** directory (see `setup.sh` / `deploy.sh` post-checks); avoids `ProtectSystem=strict` blocking SQLite opens. |
| Collector node | `collector/setup.sh` / `collector/deploy.sh` per [wiki setup-collector](wiki/setup-collector.md). |

**Shell:** `bash -n setup.sh` and `bash -n deploy.sh` after any script edits.

| Credentialed checks — placeholder smoke (optional) | From a **clone** of the repo (not on production): `./scripts/smoke_credential_checks_placeholder.sh` — isolated temp SQLite + `st_cc_run_launch` + one worker `--once` pass. Requires `sqlite3`, `php`, `python3`. **Not** shipped by `deploy.sh` (fixture only; see script header). |
| Credentialed checks — schedule selftest | From the release tree: `php scripts/st_credential_schedule_selftest.php` — cron/next-run helpers, duplicate-active skip, `launch_source`, scheduler audits (in-memory SQLite). |

---

## B. Core scan workflows

| Step | Verify |
|------|--------|
| Local scan | Queue completes; assets/findings update as expected. |
| Collector scan | Job assigned to collector; scan runs on collector host. |
| Collector submission | Results reach master (see **collector ingest** in [Troubleshooting — Collector](wiki/troubleshooting.md#collector-results-and-master-ingest)). |
| Collector ingest | `surveytrace-collector-ingest` processing; no stuck **submitted** state without explanation in UI. |
| Scan status | Transitions: queued → running → done/failed; UI matches API. |
| Scan history | List loads; **detail modal** opens; metadata sensible. |

---

## C. Inventory and findings

| Step | Verify |
|------|--------|
| Assets list | Load, sort, search; optional trusted hostname display when reconciliation enabled. |
| Host details modal | Overview, tabs, evidence (OS + identity), **Evidence — Software evidence (bounded inventory)** when inventory reconciliation applies (`software_inventory_*` + bounded **`View software evidence`** preview — **no** full package list). **Identity & inventory** shows stored vs trusted where applicable. When cred checks are in use: **Credentialed checks** summary on overview (no raw package dump in-modal). |
| Credentialed checks (admin) | **Settings → Credentialed Checks** subtab: operational summary strip, **profiles**, **jobs & runs**; filters (status, transport, profile, plugin), run row badges (partial/err), duration/targets; **run detail** sections + optional admin worker debug; **System health** cred block stays quiet when healthy. |
| Devices | List and device panel; merge flows unchanged from expectations. |
| Vulnerabilities | Filters, triage columns, host link. |
| Findings actions | Resolve / accept risk (role-gated); audit expectation understood. |
| Exports | CSV/JSON; **trusted columns** present when recon tables exist; raw columns preserved. |

---

## D. Enrichment / integrations

| Step | Verify |
|------|--------|
| Zabbix sync | Manual + scheduled path; errors visible in Enrichment / Health. |
| Match review | Links and review UI usable. |
| Apply workflows | Scope / hostname apply still **confirm-first**; audited. |
| Freshness / status | Stale/outdated signals match connector state. |
| Splunk / Grafana / syslog / webhooks / pull APIs | As deployed in your build: smoke test per [Integrations](wiki/integrations.md). |
| Deprecated pull token | No reliance on removed global pull token; per-integration tokens only (`401`/`503` as designed). |

---

## E. Trusted data model

| Step | Verify |
|------|--------|
| Schema migration | Fresh DB + existing DB: `api/db.php` bootstrap runs without error; recon tables present when migration shipped. |
| OS/platform evidence | Host modal **Evidence — OS / platform** expands; observations/assertions visible. |
| Identity evidence | **Evidence — identity** (canonical hostname); conflicting rows highlighted when applicable. |
| System Health | `trusted_data` block: quiet when healthy; warnings actionable; missing tables do not break health JSON. When cred inventory runs exist: optional software inventory readiness counters (`software_inventory_*`) appear **only as scalar counts** — never raw package arrays. **`vulnerability_correlation`** block (when tables exist) stays count-only — advisory titles/keys are not bulk health payloads. When triage migrations ship: **`vulnerability_triage`** block (counts by triage priority, stale suppressions, untriaged hints) remains **scalar-only**. |
| Exports | Additive `trusted_*` columns; null/empty handled. |
| Low-confidence fallback | Assertions at **low** confidence do not populate `trusted_*` helpers; UI falls back to stored hostname / scan OS. |

**Reference:** [TRUSTED_DATA_MODEL.md](TRUSTED_DATA_MODEL.md)

---

## F. Reporting

| Step | Verify |
|------|--------|
| Job-scope report | Loads with finished jobs in scope; empty state copy correct. |
| Inventory-scope report | Summary + top assets; trusted hostname label when API provides it. |
| Drift / trends | Where enabled for your build: sensible output or explicit empty/mismatch messaging. |
| Exports | Report exports remain consistent with filters. |
| Mode mismatch | Switching job vs inventory scope shows correct warnings (no silent wrong data). |

---

## G. Auth / security

| Step | Verify |
|------|--------|
| Local login | Password / MFA path per deployment. |
| OIDC / SSO | If configured: login and logout. |
| Breakglass | If implemented: documented escape still works. |
| RBAC | Viewer vs scan editor vs admin: gated actions return **403** where expected. |
| Health / export RBAC toggles | Restricted viewers blocked when setting enabled. |
| Rate limiting | Abuse path does not break normal use. |
| CSRF | Mutating POSTs reject without token where enforced. |
| Security headers | No regression on cookies / session for your reverse proxy setup. |

---

## H. UI / browser smoke

| Step | Verify |
|------|--------|
| Dark mode | No unreadable text or broken contrast on primary surfaces. |
| Light mode | Tonal refinement: cards, tables, modals readable. |
| Nav / tabs | Switching tabs; **scroll-to-top** behavior if implemented for your release. |
| Host modal | Nested scroll regions usable; no trapped focus regressions (quick check). |
| Narrow viewport | Primary flows usable without horizontal breakage on ~1280px and smaller. |
| Settings (admin) | Subtabs **Platform → Reference**; cards **full-width, single column**, no horizontal page overflow; **Reference** holds About / category reference only. |
| Executive dashboard mode | If enabled: charts/tables load; no JS errors in console for happy path. |

---

## I. Documentation

| Doc | Verify |
|-----|--------|
| [README.md](../README.md) | Version line and links to changelog / release notes / readiness. |
| [docs/README.md](README.md) | Index lists trusted data, credentialed checks docs, release checklist. |
| [docs/wiki/README.md](wiki/README.md) | Links to troubleshooting, deployment, trusted data references. |
| [ROADMAP.md](../ROADMAP.md) | Capability tracks reflect shipped slices vs deferred work accurately. |
| [TRUSTED_DATA_MODEL.md](TRUSTED_DATA_MODEL.md) | Matches current observation/assertion behavior. |
| [CREDENTIALED_CHECKS_ENGINE.md](CREDENTIALED_CHECKS_ENGINE.md) / [MVP plan](CREDENTIALED_CHECKS_MVP_PLAN.md) | Implemented slices and deferred scope are clearly distinguished. |
| Collector docs | [setup-collector](wiki/setup-collector.md), [troubleshooting](wiki/troubleshooting.md) mention ingest states. |
| Secret key ops docs | Deployment/troubleshooting cover `SURVEYTRACE_CRED_SECRET_KEY`, multi-node parity, backup/restore impact, no auto-rotation, **[Troubleshooting — Credential secret helper — security model](wiki/troubleshooting.md#credential-secret-helper--security-model)**, and **[Credential secret security model](wiki/security_model.md)** (helper flow, audit/retention, must-not rules). |
| Secret rewrap runbook | `scripts/rewrap_credential_secrets.php` dry-run/apply workflow and failure interpretation are documented. |
| Operational prune runbook | `scripts/prune_operational_history.php` dry-run/apply, include-runs guardrails, and backup-before-apply guidance are documented. |
| Credential runtime prune runbook | `scripts/prune_credential_runtime_history.php` dry-run default, `--apply` / `--days` / `--keep-runs`, preserving active runs and audit integrity; related WARNs in `security_runtime_audit.php`. |
| Stale recovery runbook | `scripts/recover_stale_worker_jobs.php` dry-run/apply, threshold guidance, and collector-ingest caution are documented. |
| Maintenance pre-release dry-runs | `rewrap_credential_secrets.php`, `prune_operational_history.php --older-than-days=90`, and `recover_stale_worker_jobs.php --older-than-minutes=60 --run-sync` are run (or explicitly waived) before tag. |
| Backup/restore readiness validation | `scripts/validate_backup_restore_readiness.php` runs cleanly on the target restore set before sign-off. |
| Key material parity | Restore checklist confirms the **same** `SURVEYTRACE_CRED_SECRET_KEY` value for **`surveytrace`** (env file + **`cred_decrypt_cli.php`**) and all **credential-check worker** hosts; **`php-fpm`** does not require the key in its pool env when the **sudo helper** path is configured. |
| Runtime security audit (read-only) | On master installs: `sudo php /opt/surveytrace/scripts/security_runtime_audit.php --install-root=/opt/surveytrace` exits **0** (no FAIL lines), or review WARN; **`--strict`** treats WARN as failure. Same script runs from **`setup.sh`** / **`deploy.sh`** post-checks when present. |
| Release security gate (aggregated) | From a clean checkout / install tree: `php /opt/surveytrace/scripts/release_security_gate.php` passes; on a sudoers-configured host also run with **`--require-helper-parity`**. |
| Credential API leak regression | `php /opt/surveytrace/scripts/st_credential_secret_no_leak_selftest.php` passes (blocks PEM/password/token patterns in public shapes). |

---

## J. Credential secret helper — host validation (production)

Run on the **installed master** (paths assume **`/opt/surveytrace`** and **`/etc/surveytrace/surveytrace.env`**). See [Troubleshooting — security model](wiki/troubleshooting.md#credential-secret-helper--security-model) for the full model.

| Step | Command / check | Expected |
|------|-------------------|----------|
| sudoers syntax | `sudo visudo -cf /etc/sudoers.d/surveytrace-credential-secret-helper` | Parsed OK (no errors). |
| **`www-data` cannot read env** | Shell probes below | Prints **`OK`** (not **`BAD`**) when `www-data` cannot read the file. |
| **`surveytrace` can read env** | Shell probes below | **`SURVEYTRACE_CAN_READ`**. |
| Helper status (stdin JSON) | Shell probe below | JSON includes **`available": true`** and **`key_loaded": true`** (exact key names per helper payload). |
| API encryption flag | Admin: **`GET /api/credential_profiles.php`** (or Settings load) — `encryption.available` | **`true`** when helper + key are healthy. |

```bash
sudo visudo -cf /etc/sudoers.d/surveytrace-credential-secret-helper

sudo -u www-data test -r /etc/surveytrace/surveytrace.env && echo BAD || echo OK
sudo -u surveytrace test -r /etc/surveytrace/surveytrace.env && echo SURVEYTRACE_CAN_READ || echo SURVEYTRACE_CANNOT_READ

PHPBIN=$(sudo grep '^SURVEYTRACE_PHP_CLI_BIN=' /etc/surveytrace/surveytrace.env | cut -d= -f2-)
sudo -u www-data sudo -n -u surveytrace -- "$PHPBIN" /opt/surveytrace/daemon/cred_secret_ops_cli.php <<'JSON'
{"action":"status"}
JSON
```

(Same commands are documented in [Troubleshooting — security model](wiki/troubleshooting.md#credential-secret-helper--security-model).)

### Credential helper production validation (release gate)

Before sign-off on a release that ships **cred helper / sudoers** behavior, confirm:

- [ ] **sudoers** valid (`visudo -cf` above).
- [ ] **`www-data`** cannot read **`surveytrace.env`** (probe prints **`OK`**).
- [ ] **`surveytrace`** can read **`surveytrace.env`**.
- [ ] **Helper status** returns available / key loaded as above.
- [ ] Browser / API: **`encryption.available": true`** on credential profiles.
- [ ] **Set SSH profile secret** succeeds (admin).
- [ ] **Wrong password** fails with a **safe** error (no secret echo).
- [ ] **Successful handshake** persists **`last_test_*`** as expected.
- [ ] **Job run** + **timeline** show **safe** events only (no raw secrets / unconstrained stderr).
- [ ] **Browser Network tab**: profile list/detail JSON, run detail, and timeline responses contain **no** ciphertext fields, PEM blocks, or `password=` / `Authorization:` bearer material (spot-check after handshake + run).
- [ ] **`php scripts/st_credential_secret_no_leak_selftest.php`** and **`php scripts/release_security_gate.php`** (plus **`--require-helper-parity`** where applicable) pass from the release tree.
- [ ] **`php scripts/security_runtime_audit.php --strict`** reviewed clean or WARNs explicitly accepted for this tag.

### Stale tree cleanup (post-upgrade)

- [ ] **`sudo bash deploy.sh --cleanup-stale`** — review list; then optionally **`sudo bash deploy.sh --cleanup-stale --apply`** after backup. Confirm output does **not** propose **`data/`**, **`backups/`**, env files, DB WAL/SHM, or logs.

---

## K. Known deferred items (not release blockers)

Document for operators **what is not in this release**:

- **Credentialed checks scope limits** — no WinRM execution; **no CVE matching, findings, or remediation from package inventory / `software_inventory_summary`** (inventory evidence and reconciliation only); no auto-prune daemon, no Vault/KMS integration yet.
- **CVE fusion** / multi-source reconciliation — roadmap [Data fusion](../ROADMAP.md#data-fusion-and-source-reconciliation).
- **Ownership / Defender / TeamDynamix** — deferred connector track ([Roadmap](../ROADMAP.md#ownership-and-endpoint-enrichment)).
- **Infrastructure API connectors** (Proxmox, VMware, …) — planned track, not part of stabilization scope.
- **Risk governance** (composite scoring, SLAs, suppressions) — roadmap [Risk operations](../ROADMAP.md#risk-operations-and-governance).

---

## Sign-off

| Role | Name | Date | Notes |
|------|------|------|--------|
| QA / Operator | | | |
| Release owner | | | |

### Operational lifecycle milestone closure (1.0.2)

- [ ] Secret rewrap utility validated (`st_cred_secret_rewrap_selftest.php`)
- [ ] Retention/prune utility validated (`st_operational_prune_selftest.php`)
- [ ] Credential runtime prune script exercised dry-run (`prune_credential_runtime_history.php`) before any `--apply` on production
- [ ] Stale worker recovery utility validated (`st_stale_worker_recovery_selftest.php`)
- [ ] Backup/restore readiness validator validated (`st_backup_restore_readiness_selftest.php`)
- [ ] Slice 7/8/9 selftests and slice10 reconciliation selftest pass
- [ ] Placeholder smoke passes
- [ ] `bash -n setup.sh deploy.sh` passes
- [ ] `php -l` / `python3 -m py_compile` passes on touched operational paths

### Stabilization closure (1.0.3)

- [ ] `bash -n setup.sh deploy.sh` passes; post-install/deploy **ReadWritePaths** checks pass on master
- [ ] `php -l public/index.php` (Settings markup/JS) passes
- [ ] `php scripts/st_collector_ingest_worker_hardening_selftest.php` passes (if collector ingest touched this line)
- [ ] Manual: Settings subtabs and **Credentialed Checks** subtab (admin); collector ingest journal free of SQLite open failures on fresh unit install

### Software inventory reconciliation foundations (1.0.4)

- [ ] `python3 daemon/st_software_observation_selftest.py` passes
- [ ] `php scripts/st_software_inventory_summary_selftest.php` passes
- [ ] `php scripts/st_software_inventory_evidence_selftest.php` passes
- [ ] `php scripts/st_software_inventory_diagnostics_selftest.php` passes
- [ ] `python3 daemon/cred_check_os_release_selftest.py`, `cred_check_package_inventory_selftest.py`, `cred_check_snmp_identity_selftest.py` pass
- [ ] `php scripts/st_recon_trusted_data_selftest.php` passes
- [ ] `bash scripts/smoke_credential_checks_placeholder.sh` passes (optional / CI clone)
- [ ] `bash -n setup.sh` and `bash -n deploy.sh` pass
- [ ] Manual: Host modal **Software evidence** block + **System Health** trusted-data line when non-zero software diagnostics

---

## Remaining release-readiness gaps (typical)

These are **not** always closed for a stabilization cut; track explicitly:

- Automated browser / E2E suite (if absent, manual H. section is authoritative).
- Load / concurrency testing beyond single-node smoke.
- Signed artifacts / supply-chain for distribution.
- Customer-specific reverse-proxy and SSO matrices.
