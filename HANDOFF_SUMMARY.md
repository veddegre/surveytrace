# SurveyTrace Handoff Summary (2026-05-01)

Use this as a context starter in a new conversation.

**Release:** **0.11.0** (semver in repo-root **`VERSION`**; PHP **`ST_VERSION`** via **`api/st_version.php`**, included from **`api/db.php`** and **`public/index.php`**) — **Phase 10** explainable CVE triage (`findings` evidence/confidence/risk/detection metadata; **`finding_triage.py`**; UI + export) and **Phase 11** CVE intelligence (**`cve_intel`** + **`sync_cve_intel.py`**: KEV, EPSS, OSV; feed sync **`cve_intel`** / **`all`**; **`intel`** on findings). **Phase 9** change detection remains as shipped in **0.9.0**. Prior: **0.8.x** collectors/profiles; **0.7.0** operator AI; **0.6.x** rescan parity, full-TCP safeguards, DB backup/restore, Phase 7 trash.

**Roadmap numbering:** README **Roadmap** phases **9–11** now match SQLite **`migration_phase9_*` … `migration_phase11_*`** in **`api/db.php`**. Former “upcoming” roadmap items are renumbered starting at **Phase 12** (asset lifecycle) through **Phase 17** (governance); see **`README.md` → Roadmap**.

## Where things stand

- **Phase 8 (collectors)** — MVP is in-tree: registration/check-in, job lease/submit, ingest worker path, `collector/` packaging, UI overview + Settings, schedule `collector_id`, CIDR guardrails. Treat operational hardening (ingest scale, token rotation UX, more tests) as follow-on, not “not started.”
- **Phases 1–7** — Delivered in practical scope (profiles, queue/scheduling, discovery, device identity, access hardening, scan trash/retention). Phase 5 optional follow-ons remain deferred unless needed.
- **Phases 9–11** — Delivered: change alerts + finding lifecycle (**9**), explainable triage columns + scripts (**10**), **`cve_intel`** + sync + API join (**11**).
- **Roadmap detail** — See **`README.md`** for **Phase 12+** (asset lifecycle, baselines, integrations program, UI polish, credentialed checks, governance).

## Session updates (2026-05-01)

- **0.11.0** — **`api/st_version.php`** / **`api/db.php`**: migrations **`st_migrate_phase10_finding_triage_v1`**, **`st_migrate_phase11_cve_intel_v1`**; **`ST_VERSION`** **0.11.0**. **`daemon/sync_cve_intel.py`**, **`api/feed_sync_lib.php`**, **`api/feeds.php`**, **`api/dashboard.php`**, **`api/findings.php`**, **`api/findings_export.php`**, **`public/index.php`** (Settings CVE intel + feed sync UI), **`deploy.sh`** (ship **`sync_cve_intel.py`**). **`daemon/fingerprint.py`** / **`scanner_daemon.py`** / **`sync_webfp.py`**: Proxmox + VMware classification improvements. Docs: **`README.md`** (features, changelog **0.11.0**, roadmap renumber), **`RELEASE_NOTES.md`**, this handoff.
- **0.8.2** (earlier same-day changelog work) — **`daemon/profiles.py`**: `validate_phases()` includes **`full_tcp`** / **`fast_full_tcp`** by name when allowing banner/fingerprint (empty `port_list` + `-p-` mode). **`FAST_FULL_TCP`**: `allow_version_intensity` **3** (parity with Standard Inventory). **`daemon/scanner_daemon.py`**: routed **`fast_full_tcp`** uses finite safe+standard+extra port union; LAN **`fast_full_tcp`** uses larger batches, **`-T4`**, profile-specific host timeouts. **`daemon/sync_nvd.py`** User-Agent string.

## Session updates (2026-04-30)

- **Collector install token** — UI is generate-only (confirm → API generate → one-time reveal modal with copy, no backdrop dismiss). **`api/settings.php`** rejects `collector_install_token` in POST; only **`collector_install_token_generate`** creates/rotates the value. **`collector/README.md`** install steps aligned.
- **Collector overview** — **`api/collectors.php`** adds **`online_recent_2m`** per row so summary “online (<=2m)” matches **`last_seen_at`**; **Set ranges** uses in-app modal (`public/index.php` + **`z218`** in **`public/css/app.css`**).
- **Fingerprinting** — **`daemon/fingerprint.py`**: when combined banners show Linux distro SSH (or xrdp), **3389** is omitted from the Windows port-profile pass so CPE/category are not stuck on Windows+RDP for Linux VDI/xrdp hosts.

## Next suggested steps

1. **CVE intel ops** — schedule or manually run **`sync_cve_intel.py`** after NVD sync on networks that can reach CISA / FIRST / OSV; watch **`data/feed_sync_result.json`** and **`config.cve_intel_last_sync`**.
2. **WebFP refresh** — one **`sync_webfp.py`** run post-upgrade for **`hv`** overrides on hypervisor-named Wappalyzer rows.
3. **Roadmap** — pick up **Phase 12+** from **`README.md`** (asset lifecycle, baselines, outbound integrations).

## Important files (recent touchpoints)

- **`VERSION`** (repo root / install root — bump for releases)
- `api/st_version.php` — loads **`VERSION`** → **`ST_VERSION`**
- `daemon/surveytrace_version.py` — same **`VERSION`** for Python User-Agents
- `api/db.php` — **`st_migrate_phase10_*`**, **`st_migrate_phase11_*`**
- `daemon/sync_cve_intel.py`, `daemon/finding_triage.py`, `daemon/change_detection.py`
- `api/feed_sync_lib.php`, `api/feeds.php`, `api/findings.php`, `api/findings_export.php`, `api/dashboard.php`
- `public/index.php`, `sql/schema.sql`
- `daemon/fingerprint.py`, `daemon/scanner_daemon.py`, `daemon/sync_webfp.py`, **`daemon/sqlite_pragmas.py`** (SQLite WAL / busy_timeout / mmap; env tunables in README)
- `deploy.sh` — includes **`sync_cve_intel.py`**
- `RELEASE_NOTES.md`, `README.md`

## Phase 5 reference (unchanged)

- **`docs/DEVICE_IDENTITY.md`**, **`api/devices.php`**, **`api/assets.php`**, **`daemon/scanner_daemon.py`**, **`deploy.sh`** (must ship `devices.php` with UI).
