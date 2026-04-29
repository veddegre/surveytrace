#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DB_PATH="${SURVEYTRACE_DB_PATH:-$ROOT_DIR/data/surveytrace.db}"
BACKUP_DIR="${SURVEYTRACE_DB_BACKUP_DIR:-$ROOT_DIR/data/backups}"

if [ ! -f "$DB_PATH" ]; then
  echo "database not found: $DB_PATH" >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR"

ts="$(date -u +%Y%m%d-%H%M%S)"
tmp="$BACKUP_DIR/surveytrace-$ts.db.tmp"
out="$BACKUP_DIR/surveytrace-$ts.db"

sqlite3 "$DB_PATH" ".timeout 10000" ".backup '$tmp'"
mv "$tmp" "$out"
chmod 640 "$out" 2>/dev/null || true
echo "$out"
