"""
SurveyTrace — Scheduler Daemon

Polls the scan_schedules table every 30 seconds and enqueues scan jobs
when a schedule's next_run time has arrived.

Runs alongside scanner_daemon.py as a separate systemd service.

Usage:
    python3 scheduler_daemon.py

Features:
    - Standard 5-field cron expressions (min hr dom mon dow)
    - Common preset shortcuts (@hourly, @daily, @weekly, @monthly)
    - Per-schedule enable/disable and pause/resume (paused skips cron only)
    - missed_run_policy: run_once | skip_no_run | run_all (with missed_run_max cap)
    - Updates next_run after each trigger
    - Writes schedule run history to scan_jobs with schedule_id set
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import subprocess
import time
from datetime import datetime, timezone, timedelta
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo  # Python < 3.9
from pathlib import Path

log = logging.getLogger("scheduler")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [scheduler] %(message)s",
)

DB_PATH   = Path(__file__).parent.parent / "data" / "surveytrace.db"
BACKUP_SCRIPT = Path(__file__).parent / "backup_db.sh"
BACKUP_DIR_DEFAULT = DB_PATH.parent / "backups"
POLL_SECS = 30   # check every 30 seconds


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create scan_schedules table if it doesn't exist; migrate older installs."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_schedules (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            name               TEXT NOT NULL,
            enabled            INTEGER DEFAULT 1,
            paused             INTEGER DEFAULT 0,
            cron_expr          TEXT NOT NULL,
            target_cidr        TEXT NOT NULL,
            exclusions         TEXT DEFAULT '',
            phases             TEXT DEFAULT '["passive","icmp","banner","fingerprint","cve"]',
            profile            TEXT DEFAULT 'standard_inventory',
            scan_mode          TEXT DEFAULT 'auto',
            rate_pps           INTEGER DEFAULT 5,
            inter_delay        INTEGER DEFAULT 200,
            priority           INTEGER DEFAULT 20,
            next_run           DATETIME,
            last_run           DATETIME,
            last_job_id        INTEGER DEFAULT 0,
            last_status        TEXT DEFAULT '',
            collector_id       INTEGER DEFAULT 0,
            created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
            notes              TEXT DEFAULT '',
            timezone           TEXT DEFAULT 'UTC',
            missed_run_policy  TEXT DEFAULT 'run_once',
            missed_run_max     INTEGER DEFAULT 5,
            enrichment_source_ids TEXT
        );
    """)
    existing = {row[1] for row in conn.execute("PRAGMA table_info(scan_schedules)")}
    for col, defn in [
        ("timezone", "TEXT DEFAULT 'UTC'"),
        ("paused", "INTEGER DEFAULT 0"),
        ("missed_run_policy", "TEXT DEFAULT 'run_once'"),
        ("missed_run_max", "INTEGER DEFAULT 5"),
        ("enrichment_source_ids", "TEXT"),
    ]:
        if col not in existing:
            conn.execute(f"ALTER TABLE scan_schedules ADD COLUMN {col} {defn}")

    # scan_jobs columns used when enqueueing from a schedule (may predate manual-scan UI)
    try:
        job_info = conn.execute("PRAGMA table_info(scan_jobs)").fetchall()
        if job_info:
            job_cols = {row[1] for row in job_info}
            if "enrichment_source_ids" not in job_cols:
                conn.execute("ALTER TABLE scan_jobs ADD COLUMN enrichment_source_ids TEXT")
            if "deleted_at" not in job_cols:
                conn.execute("ALTER TABLE scan_jobs ADD COLUMN deleted_at DATETIME")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_deleted_at ON scan_jobs(deleted_at, id DESC)")
    except sqlite3.OperationalError as e:
        log.warning("scan_jobs column migration skipped: %s", e)
    conn.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('scan_trash_retention_days', '30')")
    conn.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('db_backup_enabled', '0')")
    conn.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('db_backup_cron', '15 2 * * *')")
    conn.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('db_backup_retention_days', '14')")
    conn.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('db_backup_keep_count', '30')")
    conn.execute("INSERT OR IGNORE INTO config (key, value) VALUES ('db_backup_next_run', '')")


def _hard_delete_scan(conn: sqlite3.Connection, job_id: int) -> None:
    conn.execute("DELETE FROM scan_log WHERE job_id = ?", (job_id,))
    conn.execute("DELETE FROM port_history WHERE scan_id = ?", (job_id,))
    try:
        conn.execute("DELETE FROM scan_asset_snapshots WHERE job_id = ?", (job_id,))
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("DELETE FROM scan_finding_snapshots WHERE job_id = ?", (job_id,))
    except sqlite3.OperationalError:
        pass
    conn.execute("DELETE FROM scan_jobs WHERE id = ?", (job_id,))


def purge_expired_trashed_scans(conn: sqlite3.Connection) -> None:
    try:
        retention_days = int(conn.execute(
            "SELECT value FROM config WHERE key = 'scan_trash_retention_days' LIMIT 1"
        ).fetchone()[0])
    except Exception:
        retention_days = 30
    retention_days = max(1, min(365, retention_days))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).replace(tzinfo=None)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
    rows = conn.execute(
        """
        SELECT id, status, deleted_at
        FROM scan_jobs
        WHERE deleted_at IS NOT NULL
          AND deleted_at <= ?
        ORDER BY id ASC
        LIMIT 200
        """,
        (cutoff_str,),
    ).fetchall()
    if not rows:
        return
    for row in rows:
        jid = int(row["id"])
        _hard_delete_scan(conn, jid)
        try:
            conn.execute(
                """
                INSERT INTO user_audit_log
                    (actor_user_id, actor_username, target_user_id, target_username, action, details_json, source_ip)
                VALUES
                    (NULL, 'system', NULL, NULL, 'scan.job_purged',
                     json_object('job_id', ?, 'previous_status', ?, 'deleted_at', ?, 'retention_days', ?, 'source', 'scheduler_retention'),
                     '127.0.0.1')
                """,
                (jid, row["status"] or "", row["deleted_at"] or "", retention_days),
            )
        except sqlite3.OperationalError:
            pass
    log.info("Purged %d trashed scan(s) older than %d days", len(rows), retention_days)


def _cfg_get(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM config WHERE key = ? LIMIT 1", (key,)).fetchone()
    if not row:
        return default
    try:
        return str(row[0] if row[0] is not None else default)
    except Exception:
        return default


def _cfg_set(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def _audit_system(conn: sqlite3.Connection, action: str, details: dict) -> None:
    try:
        conn.execute(
            """
            INSERT INTO user_audit_log
                (actor_user_id, actor_username, target_user_id, target_username, action, details_json, source_ip)
            VALUES
                (NULL, 'system', NULL, NULL, ?, ?, '127.0.0.1')
            """,
            (action, json.dumps(details, separators=(",", ":"), ensure_ascii=False)),
        )
    except sqlite3.OperationalError:
        pass


def _purge_old_backups(retention_days: int) -> int:
    d = Path(os.getenv("SURVEYTRACE_DB_BACKUP_DIR", str(BACKUP_DIR_DEFAULT)))
    if not d.exists() or not d.is_dir():
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    n = 0
    for p in d.glob("surveytrace-*.db"):
        try:
            mtime = datetime.fromtimestamp(p.stat().st_mtime, timezone.utc)
            if mtime < cutoff:
                p.unlink(missing_ok=True)
                n += 1
        except Exception:
            continue
    return n


def _purge_backup_count(max_keep: int) -> int:
    if max_keep <= 0:
        return 0
    d = Path(os.getenv("SURVEYTRACE_DB_BACKUP_DIR", str(BACKUP_DIR_DEFAULT)))
    if not d.exists() or not d.is_dir():
        return 0
    files = []
    for p in d.glob("surveytrace-*.db"):
        try:
            files.append((p.stat().st_mtime, p))
        except Exception:
            continue
    files.sort(key=lambda t: t[0], reverse=True)
    stale = files[max_keep:]
    n = 0
    for _, p in stale:
        try:
            p.unlink(missing_ok=True)
            n += 1
        except Exception:
            continue
    return n


def maybe_run_db_backup(conn: sqlite3.Connection, now: datetime) -> None:
    enabled = _cfg_get(conn, "db_backup_enabled", "0") == "1"
    if not enabled:
        return
    expr = (_cfg_get(conn, "db_backup_cron", "15 2 * * *") or "").strip() or "15 2 * * *"
    next_run_raw = (_cfg_get(conn, "db_backup_next_run", "") or "").strip()
    now_naive = now.replace(tzinfo=None)
    now_str = now_naive.strftime("%Y-%m-%d %H:%M:%S")

    next_run: datetime | None = None
    if next_run_raw:
        try:
            next_run = _parse_utc_naive(next_run_raw)
        except Exception:
            next_run = None
    if next_run is None:
        nr = next_cron_run(expr, now_naive - timedelta(minutes=1), "UTC")
        _cfg_set(conn, "db_backup_next_run", nr.strftime("%Y-%m-%d %H:%M:%S"))
        next_run = nr
    if now_naive < next_run:
        return

    if not BACKUP_SCRIPT.exists():
        err = f"backup script missing: {BACKUP_SCRIPT}"
        log.error(err)
        _cfg_set(conn, "db_backup_last_run", now_str)
        _cfg_set(conn, "db_backup_last_status", "error")
        _cfg_set(conn, "db_backup_last_error", err)
        nr = next_cron_run(expr, now_naive, "UTC")
        _cfg_set(conn, "db_backup_next_run", nr.strftime("%Y-%m-%d %H:%M:%S"))
        _audit_system(conn, "db.backup_run_scheduled", {
            "status": "error",
            "reason": "backup_script_missing",
            "error": err,
        })
        return

    try:
        proc = subprocess.run(
            ["bash", str(BACKUP_SCRIPT)],
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if proc.returncode == 0:
            backup_path = out.splitlines()[-1].strip() if out else ""
            _cfg_set(conn, "db_backup_last_run", now_str)
            _cfg_set(conn, "db_backup_last_status", "ok")
            _cfg_set(conn, "db_backup_last_path", backup_path[:300])
            _cfg_set(conn, "db_backup_last_error", "")
            try:
                retention_days = int(_cfg_get(conn, "db_backup_retention_days", "14"))
            except Exception:
                retention_days = 14
            retention_days = max(1, min(365, retention_days))
            try:
                keep_count = int(_cfg_get(conn, "db_backup_keep_count", "30"))
            except Exception:
                keep_count = 30
            keep_count = max(1, min(500, keep_count))
            purged_age = _purge_old_backups(retention_days)
            purged_count = _purge_backup_count(keep_count)
            log.info(
                "DB backup ok: %s (purged %d by age, %d by count; keep=%d)",
                backup_path, purged_age, purged_count, keep_count
            )
            _audit_system(conn, "db.backup_run_scheduled", {
                "status": "ok",
                "path": backup_path,
                "purged_by_age": purged_age,
                "purged_by_count": purged_count,
                "retention_days": retention_days,
                "keep_count": keep_count,
            })
        else:
            msg = (err or out or f"exit {proc.returncode}")[:500]
            _cfg_set(conn, "db_backup_last_run", now_str)
            _cfg_set(conn, "db_backup_last_status", "error")
            _cfg_set(conn, "db_backup_last_error", msg)
            log.error("DB backup failed: %s", msg)
            _audit_system(conn, "db.backup_run_scheduled", {
                "status": "error",
                "error": msg,
                "exit_code": proc.returncode,
            })
    except Exception as e:
        msg = str(e)[:500]
        _cfg_set(conn, "db_backup_last_run", now_str)
        _cfg_set(conn, "db_backup_last_status", "error")
        _cfg_set(conn, "db_backup_last_error", msg)
        log.error("DB backup exception: %s", msg)
        _audit_system(conn, "db.backup_run_scheduled", {
            "status": "error",
            "error": msg,
            "reason": "exception",
        })

    nr = next_cron_run(expr, now_naive, "UTC")
    _cfg_set(conn, "db_backup_next_run", nr.strftime("%Y-%m-%d %H:%M:%S"))


# ---------------------------------------------------------------------------
# Cron expression parser
# ---------------------------------------------------------------------------
PRESETS = {
    "@yearly":   "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
    "@monthly":  "0 0 1 * *",
    "@weekly":   "0 0 * * 0",
    "@daily":    "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@hourly":   "0 * * * *",
}


def parse_cron(expr: str) -> tuple[str, str, str, str, str]:
    """
    Parse a cron expression into 5 fields.
    Supports standard 5-field cron and @preset shortcuts.
    Returns (minute, hour, dom, month, dow).
    """
    expr = expr.strip()
    if expr in PRESETS:
        expr = PRESETS[expr]
    parts = expr.split()
    if len(parts) != 5:
        raise ValueError(f"Invalid cron expression: {repr(expr)} — expected 5 fields")
    return tuple(parts)  # type: ignore


def _matches_field(value: int, field: str) -> bool:
    """
    Check if a numeric value matches a cron field.
    Supports: * / , -
    """
    if field == "*":
        return True

    for part in field.split(","):
        part = part.strip()
        if "/" in part:
            # Step: */5 or 1-30/5
            range_part, step_str = part.split("/", 1)
            step = int(step_str)
            if range_part == "*":
                start, end = 0, 59
            elif "-" in range_part:
                start, end = map(int, range_part.split("-"))
            else:
                start = end = int(range_part)
            if start <= value <= end and (value - start) % step == 0:
                return True
        elif "-" in part:
            # Range: 1-5
            lo, hi = map(int, part.split("-"))
            if lo <= value <= hi:
                return True
        else:
            # Exact value
            if value == int(part):
                return True

    return False


def cron_matches(expr: str, dt: datetime) -> bool:
    """Return True if the datetime matches the cron expression."""
    try:
        minute, hour, dom, month, dow = parse_cron(expr)
    except ValueError:
        return False

    # dow: 0=Sunday in cron, Python weekday: 0=Monday
    # Convert: cron_dow = (python_weekday + 1) % 7
    cron_dow = (dt.weekday() + 1) % 7

    return (
        _matches_field(dt.minute,  minute) and
        _matches_field(dt.hour,    hour)   and
        _matches_field(dt.day,     dom)    and
        _matches_field(dt.month,   month)  and
        _matches_field(cron_dow,   dow)
    )


def next_cron_run(expr: str, after: datetime, tz_name: str = "UTC") -> datetime:
    """
    Calculate the next run time after a given datetime.
    Cron expression is interpreted in tz_name timezone.
    Returns UTC datetime.
    """
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = timezone.utc

    # Convert after to local time for cron matching
    if after.tzinfo is None:
        after_utc = after.replace(tzinfo=timezone.utc)
    else:
        after_utc = after

    # Work in local timezone for cron matching
    after_local = after_utc.astimezone(tz)
    dt_local = after_local.replace(second=0, microsecond=0) + timedelta(minutes=1)

    for _ in range(366 * 24 * 60):  # max 1 year of minutes
        if cron_matches(expr, dt_local):
            # Convert back to UTC for storage
            return dt_local.astimezone(timezone.utc).replace(tzinfo=None)
        dt_local += timedelta(minutes=1)
    raise ValueError(f"Could not find next run for cron: {repr(expr)}")


# ---------------------------------------------------------------------------
# Job enqueueing
# ---------------------------------------------------------------------------
def enqueue_job(conn: sqlite3.Connection, schedule: dict, label_suffix: str = "") -> int:
    """
    Create a scan_jobs entry from a schedule.
    Returns the new job ID.
    """
    label = f"[Scheduled] {schedule['name']}{label_suffix}"
    enr_ids = schedule.get("enrichment_source_ids")
    conn.execute("""
        INSERT INTO scan_jobs
            (target_cidr, label, exclusions, phases, rate_pps, inter_delay,
             scan_mode, profile, priority, schedule_id, created_by, enrichment_source_ids)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'scheduler', ?)
    """, (
        schedule["target_cidr"],
        label,
        schedule["exclusions"] or "",
        schedule["phases"] or '["passive","icmp","banner","fingerprint","cve"]',
        schedule["rate_pps"] or 5,
        schedule["inter_delay"] or 200,
        schedule["scan_mode"] or "auto",
        schedule["profile"] or "standard_inventory",
        schedule["priority"] or 20,
        schedule["id"],
        enr_ids,
    ))
    job_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Log the schedule trigger
    conn.execute("""
        INSERT INTO scan_log (job_id, ts, level, ip, message)
        VALUES (?, datetime('now'), 'INFO', '', ?)
    """, (job_id, f"Job enqueued by scheduler — schedule: {schedule['name']} (id={schedule['id']})"))

    return job_id


def _parse_utc_naive(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")


def _missed_fire_times(
    expr: str,
    first_due: datetime,
    end: datetime,
    tz_name: str,
    max_n: int,
) -> list[datetime]:
    """UTC-naive cron fire times from first_due through end, at most max_n slots."""
    slots: list[datetime] = []
    cur = first_due
    while cur <= end and len(slots) < max_n:
        slots.append(cur)
        cur = next_cron_run(expr, cur, tz_name)
    return slots


def process_due_schedule(conn: sqlite3.Connection, row: sqlite3.Row, now: datetime) -> None:
    """Enqueue according to missed_run_policy and advance next_run."""
    s = dict(row)
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    expr = s["cron_expr"]
    tz_name = s.get("timezone") or "UTC"
    policy = (s.get("missed_run_policy") or "run_once").strip().lower()
    if policy not in ("run_once", "skip_no_run", "run_all"):
        policy = "run_once"
    try:
        max_catchup = int(s.get("missed_run_max") or 5)
    except (TypeError, ValueError):
        max_catchup = 5
    max_catchup = max(1, min(100, max_catchup))

    nr = next_cron_run(expr, now, tz_name)
    nr_str = nr.strftime("%Y-%m-%d %H:%M:%S")

    if policy == "skip_no_run":
        conn.execute(
            """
            UPDATE scan_schedules
            SET next_run = ?
            WHERE id = ?
            """,
            (nr_str, s["id"]),
        )
        log.info(
            "Schedule '%s' (id=%d) overdue — skip_no_run: advancing next_run to %s",
            s["name"],
            s["id"],
            nr_str,
        )
        return

    if policy == "run_all":
        first_due = _parse_utc_naive(s["next_run"])
        slots = _missed_fire_times(expr, first_due, now, tz_name, max_catchup)
        if not slots:
            conn.execute(
                "UPDATE scan_schedules SET next_run = ? WHERE id = ?",
                (nr_str, s["id"]),
            )
            return
        last_job_id = 0
        for i, _slot in enumerate(slots):
            suf = "" if i == 0 else " (catch-up)"
            last_job_id = enqueue_job(conn, s, suf)
        conn.execute(
            """
            UPDATE scan_schedules
            SET last_run = ?, last_job_id = ?, next_run = ?
            WHERE id = ?
            """,
            (now_str, last_job_id, nr_str, s["id"]),
        )
        log.info(
            "Schedule '%s' (id=%d) run_all: queued %d job(s), next run: %s",
            s["name"],
            s["id"],
            len(slots),
            nr_str,
        )
        return

    # run_once — single job, align to next cron boundary after now
    job_id = enqueue_job(conn, s)
    conn.execute(
        """
        UPDATE scan_schedules
        SET last_run = ?, last_job_id = ?, next_run = ?
        WHERE id = ?
        """,
        (now_str, job_id, nr_str, s["id"]),
    )
    log.info("Schedule '%s' → job #%d queued, next run: %s", s["name"], job_id, nr_str)


# ---------------------------------------------------------------------------
# Main scheduler loop
# ---------------------------------------------------------------------------
def main() -> None:
    log.info("SurveyTrace scheduler daemon starting (db: %s)", DB_PATH)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Ensure schema exists
    with db_conn() as conn:
        ensure_schema(conn)

        # Initialize next_run for schedules that don't have one
        schedules = conn.execute("""
            SELECT * FROM scan_schedules
            WHERE enabled = 1 AND COALESCE(paused, 0) = 0 AND next_run IS NULL
        """).fetchall()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        for s in schedules:
            try:
                nr = next_cron_run(s["cron_expr"], now, s.get("timezone") or "UTC")
                conn.execute(
                    "UPDATE scan_schedules SET next_run=? WHERE id=?",
                    (nr.strftime("%Y-%m-%d %H:%M:%S"), s["id"])
                )
                log.info("Schedule '%s' next run: %s", s["name"], nr)
            except Exception as e:
                log.warning("Could not compute next_run for schedule '%s': %s", s["name"], e)

    log.info("Scheduler ready — polling every %ds", POLL_SECS)

    while True:
        try:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            now_str = now.strftime("%Y-%m-%d %H:%M:%S")

            with db_conn() as conn:
                purge_expired_trashed_scans(conn)
                maybe_run_db_backup(conn, now)
                # Find all enabled schedules due to run
                due = conn.execute("""
                    SELECT * FROM scan_schedules
                    WHERE enabled = 1
                      AND COALESCE(paused, 0) = 0
                      AND next_run IS NOT NULL
                      AND next_run <= ?
                    ORDER BY next_run ASC
                """, (now_str,)).fetchall()

                for schedule in due:
                    s = dict(schedule)
                    log.info("Schedule '%s' (id=%d) is due — policy=%s",
                             s["name"], s["id"],
                             (s.get("missed_run_policy") or "run_once"))

                    try:
                        process_due_schedule(conn, schedule, now)
                    except Exception as e:
                        log.error("Failed to enqueue job for schedule '%s': %s",
                                  s["name"], e)

        except Exception as e:
            log.exception("Scheduler loop error: %s", e)

        time.sleep(POLL_SECS)


if __name__ == "__main__":
    main()
