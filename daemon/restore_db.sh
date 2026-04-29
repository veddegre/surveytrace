#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DB_PATH="${SURVEYTRACE_DB_PATH:-$ROOT_DIR/data/surveytrace.db}"
BACKUP_DIR="${SURVEYTRACE_DB_BACKUP_DIR:-$ROOT_DIR/data/backups}"

if [ "${1:-}" = "" ]; then
  echo "Usage: $0 <backup-file-or-name>" >&2
  echo "Example: $0 surveytrace-20260429-021500.db" >&2
  exit 1
fi

arg="$1"
if [[ "$arg" = /* ]]; then
  SRC="$arg"
else
  SRC="$BACKUP_DIR/$arg"
fi

if [ ! -f "$SRC" ]; then
  echo "Backup file not found: $SRC" >&2
  exit 1
fi

echo "This will overwrite the live SurveyTrace DB:"
echo "  target: $DB_PATH"
echo "  source: $SRC"
echo
read -r -p "Stop services and continue restore? Type YES: " ans
if [ "$ans" != "YES" ]; then
  echo "Aborted."
  exit 1
fi

systemctl stop surveytrace-daemon surveytrace-scheduler || true

ts="$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$(dirname "$DB_PATH")"
if [ -f "$DB_PATH" ]; then
  cp -a "$DB_PATH" "${DB_PATH}.pre-restore-$ts"
fi
cp -a "$SRC" "$DB_PATH"
chmod 660 "$DB_PATH" 2>/dev/null || true

systemctl start surveytrace-daemon surveytrace-scheduler
echo "Restore complete: $DB_PATH"
