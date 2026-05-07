# Release readiness checklist

Use this checklist before tagging a **maintenance / stabilization** release. It is **operator- and QA-oriented**: confirm behavior, not new feature work.

**Related:** [CHANGELOG.md](../CHANGELOG.md) · [RELEASE_NOTES.md](../RELEASE_NOTES.md) · [Trusted data model](TRUSTED_DATA_MODEL.md)

---

## A. Install / deploy

| Step | Verify |
|------|--------|
| Fresh **master** install | `sudo bash setup.sh` (or `SURVEYTRACE_SETUP=master`) completes; post-install validation passes. |
| **deploy.sh** on existing master | Completes; post-deploy checks **PASS**; no missing `api/*.php` from explicit list. |
| Required files present | `api/lib_reconciliation.php`, `api/recon_diagnostics.php`, `daemon/recon_observations.py`, `docs/TRUSTED_DATA_MODEL.md` (and cred-checks design docs if shipped) under `/opt/surveytrace`. |
| Permissions | `api/`: `surveytrace:www-data`, dirs `2750`, files `640`; `data/`: `2770` / `660` on DB; `daemon/`: `surveytrace:surveytrace`. |
| PHP syntax | `php -l` on changed API files (or run deploy output which includes reconciliation API checks). |
| Python syntax | `python3 -m py_compile daemon/recon_observations.py` (and deploy validates after copy). |
| systemd | `surveytrace-daemon`, `surveytrace-scheduler`, `surveytrace-collector-ingest` **active** (master). |
| systemd sandbox / SQLite | Installed units for master daemons that open the DB include **`ReadWritePaths`** for the SurveyTrace **`data`** directory (see `setup.sh` / `deploy.sh` post-checks); avoids `ProtectSystem=strict` blocking SQLite opens. |
| Collector node | `collector/setup.sh` / `collector/deploy.sh` per [wiki setup-collector](wiki/setup-collector.md). |

**Shell:** `bash -n setup.sh` and `bash -n deploy.sh` after any script edits.

| Credentialed checks — slice 6 placeholder (optional) | From a **clone** of the repo (not on production): `./scripts/smoke_credential_checks_placeholder.sh` — isolated temp SQLite + `st_cc_run_launch` + one worker `--once` pass. Requires `sqlite3`, `php`, `python3`. **Not** shipped by `deploy.sh` (fixture only; see script header). |

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
| Host details modal | Overview, tabs, evidence (OS + identity), **Identity & inventory** shows stored vs trusted where applicable. When cred checks are in use: **Credentialed checks** summary on overview (no raw package dump in-modal). |
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
| System Health | `trusted_data` block: quiet when healthy; warnings actionable; missing tables do not break health JSON. |
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
| Secret key ops docs | Deployment/troubleshooting cover `SURVEYTRACE_CRED_SECRET_KEY`, multi-node parity, backup/restore impact, and no auto-rotation. |
| Secret rewrap runbook | `scripts/rewrap_credential_secrets.php` dry-run/apply workflow and failure interpretation are documented. |
| Operational prune runbook | `scripts/prune_operational_history.php` dry-run/apply, include-runs guardrails, and backup-before-apply guidance are documented. |
| Stale recovery runbook | `scripts/recover_stale_worker_jobs.php` dry-run/apply, threshold guidance, and collector-ingest caution are documented. |
| Maintenance pre-release dry-runs | `rewrap_credential_secrets.php`, `prune_operational_history.php --older-than-days=90`, and `recover_stale_worker_jobs.php --older-than-minutes=60 --run-sync` are run (or explicitly waived) before tag. |
| Backup/restore readiness validation | `scripts/validate_backup_restore_readiness.php` runs cleanly on the target restore set before sign-off. |
| Key material parity | Restore checklist confirms `SURVEYTRACE_CRED_SECRET_KEY` parity across web/API and worker nodes for credentialed checks. |

---

## J. Known deferred items (not release blockers)

Document for operators **what is not in this release**:

- **Credentialed checks scope limits** — no WinRM execution, no CVE/finding/remediation from package inventory, no auto-prune daemon, no Vault/KMS integration yet.
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

---

## Remaining release-readiness gaps (typical)

These are **not** always closed for a stabilization cut; track explicitly:

- Automated browser / E2E suite (if absent, manual H. section is authoritative).
- Load / concurrency testing beyond single-node smoke.
- Signed artifacts / supply-chain for distribution.
- Customer-specific reverse-proxy and SSO matrices.
