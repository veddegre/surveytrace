# SurveyTrace Handoff Summary (2026-04-27)

Use this as a context starter in a new conversation.

**Release:** **0.5.0** (`ST_VERSION` in `api/db.php`) — device identity (Phase 5) is the headline change.

## Where things stand

- **Phase 5 (device identity)** is **delivered** in-repo: schema + migrations, scanner linkage, APIs, UI, merge, docs. See **`docs/DEVICE_IDENTITY.md`** and the **Phase 5** changelog block in **`README.md`**.
- **Roadmap:** **`README.md`** — **Phase 6** is **identity & access** (SAML/OIDC, **local accounts** with **TOTP** + **recovery codes**, **possible** **WebAuthn/FIDO2/passkeys** if scope allows, RBAC); **Phase 7** is **collector architecture** (distributed agents / multi-site); **Phase 13** includes a **possible** frontend modularization pass to split the growing `public/index.php` into maintainable units. Phase 5 optional follow-ons (split/reassign, findings-by-device, `device_identifiers`, orphan cleanup) are **explicitly deferred** unless a concrete need appears.

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

## Phase 7 — Collector architecture (suggested implementation order, thin slice first)

1. **`collectors` table** (+ migrations in `api/db.php` / daemon if needed) — `hostname`, `site`, token hash, `last_seen`, `status`, etc.
2. **Registration** — issue raw token once, store hash; document rotation.
3. **`api/collector_checkin.php`** — bearer token auth, update `last_seen` + optional payload.
4. **`api/collector_jobs.php`** — atomic **lease** of one job for a collector (SQLite-safe claim pattern).
5. **`api/collector_submit.php`** — idempotent result submission, tie into existing `scan_jobs` / asset pipeline as appropriate.
6. **`daemon/collector_agent.py`** (or `collector_agent.py` at repo root) — minimal loop: check-in → poll → execute stub or delegate → submit.
7. **Management UI** — list collectors, last seen, revoke token, assign schedules (can follow after API is stable).
8. **Rate limits + health** — per-collector caps; surface in **`/api/health.php`** or dedicated status.
9. **First remote deploy** (e.g. GVSU) — validate TLS, clocks, and firewall paths against the slice above.

## Optional housekeeping (any phase)

- Feed sync async / last sync duration in Settings (older handoff items).
- Smoke tests: dashboard legacy schema, `devices.php` merge, migration idempotency.
