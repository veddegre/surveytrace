# SurveyTrace Handoff Summary (2026-04-28)

Use this as a context starter in a new conversation.

**Release:** **0.6.0** (`ST_VERSION` in `api/db.php`) — identity/auth hardening + profile UX are the headline changes.

## Where things stand

- **Phase 5 (device identity)** is **delivered** in-repo: schema + migrations, scanner linkage, APIs, UI, merge, docs. See **`docs/DEVICE_IDENTITY.md`** and the **Phase 5** changelog block in **`README.md`**.
- **Roadmap:** **`README.md`** — **Phase 6** is **identity & access** (OIDC, **local accounts** with **TOTP** + **recovery codes**, **possible** **WebAuthn/FIDO2/passkeys** if scope allows, RBAC); **Phase 7** is **scan delete hardening** (Trash + retention); **Phase 8** is **collector architecture** (distributed agents / multi-site); **Phase 10** is CVE quality improvements before **Phase 11** asset lifecycle; **Phase 13** is a multi-part integrations program (Grafana, Zabbix, Proxmox, TrueNAS, syslog, plus stubbed connector completion); **Phase 14** includes a **possible** frontend modularization pass to split the growing `public/index.php` into maintainable units. Phase 5 optional follow-ons (split/reassign, findings-by-device, `device_identifiers`, orphan cleanup) are **explicitly deferred** unless a concrete need appears.

## Session updates (2026-04-27 late)

- **Scan history UX:** dedicated **Scan history** page added; queue visible on both **Scan control** and **Scan history**.
- **Actions:** run rows/details now support **Re-run** and **Delete** (`POST /api/scan_delete.php`); delete is blocked for queued/running/retrying jobs.
- **Snapshot persistence:** daemon writes **`scan_asset_snapshots`** and **`scan_finding_snapshots`** at scan completion; schema + migrations added in `sql/schema.sql`, `api/db.php`, and daemon startup migrations.
- **Detail fallbacks:** `api/scan_history.php?id=` resolves assets via snapshots first, then legacy `assets.last_scan_id`, then `port_history` for older scans.
- **Diffing:** scan detail compares against previous or selected run (`compare_to`) with scope (`compare_scope=any|target|profile|both`) and reports host/port/CVE deltas, including explicit added/removed port lists.
- **Host/device history:** `api/assets.php?id=` returns per-host scan change history; `api/devices.php?id=` returns aggregated device scan history (across linked assets) with deltas and “View run details” navigation back to scan detail modal.
- **UI reliability fixes:** click handlers for scan history/detail navigation moved to delegated handlers to avoid inline click issues in stricter browser environments.
- **Label cleanup:** re-run/retry labels normalized in `api/scan_start.php` to avoid repeated suffix stacking.

## Session updates (2026-04-28 auth hardening + UX)

- **SSO scope:** removed SAML bridge path; SurveyTrace now uses **OIDC** as the only SSO mode (with compatibility mapping of legacy `auth_mode=saml` to `oidc`).
- **OIDC security:** added JWKS-based `id_token` signature verification in `api/auth_oidc.php`.
- **RBAC enforcement pass:** expanded `st_require_role()` coverage across key read/write APIs and aligned role-aware control visibility in the UI.
- **Access Control UX:** moved auth/SSO/password-policy/user-admin controls into a dedicated **Access control** page; OIDC-only settings are conditionally shown only when auth mode is set to OIDC.
- **MFA UX:** setup now includes QR enrollment and copyable setup URI; recovery codes are displayed in a copy/download/print panel instead of alert-only text.
- **MFA disable:** moved from browser prompt to an in-app modal and accepts OTP or recovery code.
- **Admin user management:** local user edit/create flows now use modal-based temporary-password handling (with confirm field), plus per-user **Clear MFA** action and quick-save for profile/role/disabled updates.
- **Temporary password policy:** admin-set passwords for local users are treated as temporary (`must_change_password=1`) and force a change at next login.
- **Self-service profile:** added **My profile** UI for current user (display name, email); local users can self-manage password/MFA there; OIDC users see IdP-managed messaging.
- **Schema updates:** `users` table now includes `must_change_password`, `display_name`, and `email` with startup migrations in `api/db.php`.
- **Audit expansion:** historical user audit now includes auth + account lifecycle events and scan/schedule operator actions (queue/re-run/delete/run-now/pause/resume/toggle).

## Next suggested steps

1. **Backfill utility (optional):** best-effort script to populate `scan_asset_snapshots` / `scan_finding_snapshots` for older runs using `port_history` + current findings metadata.
2. **Diff granularity:** optional host-port pair detail table in scan diff modal (not only unique port list + counts).
3. **Delete hardening (requested / next phase):** switch to soft delete with a **Trash** view; keep runs for configurable **X days** (e.g. `scan_trash_retention_days`) before automatic purge.
   - Suggested shape: `scan_jobs.deleted_at` + filter controls (`active` / `trash`) + daemon or scheduler purge task.
4. **Tests:** add regression tests for auth flows (temporary password -> forced change, local MFA setup/disable, recovery code consumption, admin clear-MFA), plus access-control page regressions (admin/non-admin visibility), and existing scan-history compare/snapshot persistence checks.
5. **Docs cleanup:** if these ship as a release, move README `Unreleased` bullets into a versioned block and include Access-control page notes and audit-scope expansion in release notes.

## Phase 5 — What shipped (reference)

- **`devices`** + **`assets.device_id`**; migration flag **`config.migration_device_identity_v1`**; PHP (`api/db.php`) + daemon startup migration.
- **`daemon/scanner_daemon.py`**: `ensure_device_id_for_upsert` / merge path; MAC onto **`devices.primary_mac_norm`** when learned.
- **API:** **`api/devices.php`** — `GET` list + detail; **`POST`** `action=merge` (`survivor_id`, `merge_ids`); **`api/assets.php`** `device_id` filter + sort; **`api/export.php`** `device_id`; **`api/dashboard.php`** includes `device_id` in top vulnerable assets.
- **UI (`public/index.php` + `public/css/app.css`):** Devices tab; device detail panel + merge; Assets (device column, filter, numeric id + Enter, clear filters); dashboard device links; device banner CSS fix (`.device-filter-banner.hide`).
- **`deploy.sh`:** copies **`api/devices.php`** (required on server or Devices tab 404s).
- **Un-merge:** intentionally **not** implemented (would need merge audit / per-asset history).

## Important files (Phase 5)

- `docs/DEVICE_IDENTITY.md`
- `sql/schema.sql`
- `api/db.php`, `api/devices.php`, `api/assets.php`, `api/export.php`, `api/dashboard.php`
- `daemon/scanner_daemon.py`
- `public/index.php`, `public/css/app.css`
- `deploy.sh`
- `README.md` (roadmap + changelog)

## Current behavior expectations

- Every asset has a **`device_id`** after migration; scanner keeps it stable on IP upsert.
- **Merge** reassigns assets to the survivor and **deletes** merged device rows; a line is written to **`scan_log`** (`job_id` null).
- **Devices** tab and **`/api/devices.php`** must be deployed together (`deploy.sh`).

## Phase 8 — Collector architecture (suggested implementation order, thin slice first)

1. **`collectors` table** (+ migrations in `api/db.php` / daemon if needed) — `hostname`, `site`, token hash, `last_seen`, `status`, etc.
2. **Registration** — issue raw token once, store hash; document rotation.
3. **`api/collector_checkin.php`** — bearer token auth, update `last_seen` + optional payload.
4. **`api/collector_jobs.php`** — atomic **lease** of one job for a collector (SQLite-safe claim pattern).
5. **`api/collector_submit.php`** — idempotent result submission into an ingest queue/artifact store (not direct heavy upserts in request path).
6. **`daemon/collector_agent.py`** (or `collector_agent.py` at repo root) — minimal loop: check-in → poll → execute stub or delegate → submit.
7. **Ingest worker on master** — apply queued collector payloads into `assets` / findings / snapshots; run fingerprinting + CVE enrichment asynchronously; track state (`received`/`applying`/`done`/`failed`) with retries.
8. **Management UI** — list collectors, last seen, revoke token, assign schedules (can follow after API is stable).
9. **Rate limits + health** — per-collector caps; surface in **`/api/health.php`** or dedicated status.
10. **First remote deploy** (e.g. GVSU) — validate TLS, clocks, and firewall paths against the slice above.

## Optional housekeeping (any phase)

- Feed sync async / last sync duration in Settings (older handoff items).
- Smoke tests: dashboard legacy schema, `devices.php` merge, migration idempotency, and auth contract checks (`/api/auth.php?status=1`, role-gated endpoints, local-vs-oidc profile behavior).
