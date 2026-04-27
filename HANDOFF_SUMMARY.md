# SurveyTrace Handoff Summary (2026-04-27)

Use this as context starter in a new conversation.

## What Was Done

### 1) Scheduling and scan-history foundation
- Added scan history support with persisted per-run snapshot summary.
- Added `summary_json` to `scan_jobs` schema/migrations.
- Added `GET /api/scan_history.php`:
  - list mode (`?limit=N`)
  - detail mode (`?id=<job_id>`) including linked assets + log tail.
- Updated `scan_status.php` history payload to include parsed summary.
- Updated scanner daemon completion path to write summary metrics (ports/categories/findings/etc.).

### 2) UI overhaul (less “AI-generated” look)
- Refactored large amount of inline styling in `public/index.php` into reusable classes in `public/css/app.css`.
- Shifted to an enterprise-clean visual direction (flatter surfaces, calmer palette, tighter radius, cleaner tables/cards).
- Changed primary UI font to `Open Sans` (kept monospace for technical values).
- Added light-mode-safe category badge palettes.

### 3) Theme and dashboard presentation behavior
- Added persistent theme control in top bar:
  - `Theme: Dark | Light | Auto`
  - Auto follows OS `prefers-color-scheme` and updates live on system change.
- Added/improved Executive view:
  - clearer presentation-focused dashboard mode
  - compact icon-style sidebar in executive mode
  - auto-switches to dashboard when enabled
  - restores previous tab when disabled.

### 4) Feed sync UX and reliability fixes
- Improved Settings sync UX:
  - visible in-progress / success / failure status lines
  - button busy indicator + “Syncing…” label
  - output modal keeps latest run output.
- Enforced single-sync-at-a-time logic in UI:
  - second click shows “sync already running” message.
- Fixed confusing busy-state behavior so only the clicked sync button shows active spinner.
- Feed API timeout tuned to bounded value (`set_time_limit(240)`) to avoid indefinite hangs.

### 5) “Everything stuck on Loading” incident fix
- Root cause found and fixed in `api/dashboard.php`:
  - endpoint crashed on older DBs (`no such column: label`) after sync/reload.
- Added legacy `scan_jobs` column migrations in `dashboard.php` so it self-heals older schemas.

## Important Files Changed

- `public/index.php`
- `public/css/app.css`
- `api/dashboard.php`
- `api/feeds.php`
- `api/scan_status.php`
- `api/scan_history.php` (new)
- `api/db.php`
- `daemon/scanner_daemon.py`
- `sql/schema.sql`
- `README.md`

## Current Behavior Expectations

- App loads without “stuck on Loading” on older DBs.
- Theme toggle cycles Dark/Light/Auto and persists.
- Executive mode is noticeably different and restores prior tab on exit.
- Clicking a sync button shows clear progress and only that action appears active.
- If a sync is already running, additional sync clicks are blocked with a message.

## Suggested Next Steps

1. Make feed sync fully asynchronous/backgrounded server-side to avoid request blocking risk.
2. Add a tiny “last sync duration” + “last sync exit code” display in Settings.
3. Add one integration test or smoke script for:
   - dashboard endpoint on legacy schema
   - sync button state transitions.
4. Optional: finish eliminating remaining inline styles in `public/index.php`.
