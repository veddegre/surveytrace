#!/usr/bin/env bash
# Credentialed Checks slice 6 — placeholder E2E smoke (isolated SQLite).
#
# Creates a temporary database from sql/schema.sql, runs the PHP fixture driver
# (seed + st_cc_run_launch + credential_check_worker.py --once + assertions),
# then deletes the temp file.
#
# Usage (from repo root):
#   ./scripts/smoke_credential_checks_placeholder.sh
#
# Requires: sqlite3, php, python3 on PATH. No network. Does not touch data/surveytrace.db.
#
# Worker runs with SURVEYTRACE_CRED_CHECK_PLACEHOLDER_ONLY=1 (no real SSH; slice-6-style skips).
# Not covered: HTTP APIs (auth/CSRF), scope-based targets, experimental launch gating,
# UI, or multiple worker/concurrency scenarios. Includes cancel-before-lease via PHP ops.
# Not deployed by deploy.sh (developer/CI fixture only).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCHEMA="$ROOT/sql/schema.sql"
PHP="$ROOT/scripts/smoke_credential_checks_placeholder.php"

if [[ ! -f "$SCHEMA" ]]; then
  echo "FAIL: schema not found: $SCHEMA" >&2
  exit 1
fi
if [[ ! -f "$PHP" ]]; then
  echo "FAIL: driver not found: $PHP" >&2
  exit 1
fi

TMP="$(mktemp "${TMPDIR:-/tmp}/st-smoke-cred-placeholder.XXXXXX.db")"
cleanup() { rm -f "$TMP"; }
trap cleanup EXIT

sqlite3 "$TMP" ".read $SCHEMA" >/dev/null

php "$PHP" "$TMP"
