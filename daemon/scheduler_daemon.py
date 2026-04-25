"""
SurveyTrace — Scheduler Daemon

Polls the scan_schedules table every minute and enqueues scan jobs
when a schedule's next_run time has arrived.

Runs alongside scanner_daemon.py as a separate systemd service.

Usage:
    python3 scheduler_daemon.py

Features:
    - Standard 5-field cron expressions (min hr dom mon dow)
    - Common preset shortcuts (@hourly, @daily, @weekly, @monthly)
    - Missed run detection (catches up if server was down)
    - Per-schedule enable/disable
    - Updates next_run after each trigger
    - Writes schedule run history to scan_jobs with schedule_id set
"""

from __future__ import annotations

import json
import logging
import sqlite3
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
    """Create scan_schedules table if it doesn't exist."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_schedules (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            enabled      INTEGER DEFAULT 1,
            cron_expr    TEXT NOT NULL,
            target_cidr  TEXT NOT NULL,
            exclusions   TEXT DEFAULT '',
            phases       TEXT DEFAULT '["passive","icmp","banner","fingerprint","cve"]',
            profile      TEXT DEFAULT 'standard_inventory',
            scan_mode    TEXT DEFAULT 'auto',
            rate_pps     INTEGER DEFAULT 5,
            inter_delay  INTEGER DEFAULT 200,
            priority     INTEGER DEFAULT 20,
            next_run     DATETIME,
            last_run     DATETIME,
            last_job_id  INTEGER DEFAULT 0,
            last_status  TEXT DEFAULT '',
            collector_id INTEGER DEFAULT 0,
            created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
            notes        TEXT DEFAULT ''
        );
    """)


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
def enqueue_job(conn: sqlite3.Connection, schedule: dict) -> int:
    """
    Create a scan_jobs entry from a schedule.
    Returns the new job ID.
    """
    conn.execute("""
        INSERT INTO scan_jobs
            (target_cidr, label, exclusions, phases, rate_pps, inter_delay,
             scan_mode, profile, priority, schedule_id, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'scheduler')
    """, (
        schedule["target_cidr"],
        f"[Scheduled] {schedule['name']}",
        schedule["exclusions"] or "",
        schedule["phases"] or '["passive","icmp","banner","fingerprint","cve"]',
        schedule["rate_pps"] or 5,
        schedule["inter_delay"] or 200,
        schedule["scan_mode"] or "auto",
        schedule["profile"] or "standard_inventory",
        schedule["priority"] or 20,
        schedule["id"],
    ))
    job_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    # Log the schedule trigger
    conn.execute("""
        INSERT INTO scan_log (job_id, ts, level, ip, message)
        VALUES (?, datetime('now'), 'INFO', '', ?)
    """, (job_id, f"Job enqueued by scheduler — schedule: {schedule['name']} (id={schedule['id']})"))

    return job_id


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
        schedules = conn.execute(
            "SELECT * FROM scan_schedules WHERE enabled=1 AND next_run IS NULL"
        ).fetchall()
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
                # Find all enabled schedules due to run
                due = conn.execute("""
                    SELECT * FROM scan_schedules
                    WHERE enabled = 1
                      AND next_run IS NOT NULL
                      AND next_run <= ?
                    ORDER BY next_run ASC
                """, (now_str,)).fetchall()

                for schedule in due:
                    s = dict(schedule)
                    log.info("Schedule '%s' (id=%d) is due — enqueueing job",
                             s["name"], s["id"])

                    try:
                        job_id = enqueue_job(conn, s)

                        # Calculate next run time
                        nr = next_cron_run(s["cron_expr"], now, s.get("timezone") or "UTC")
                        nr_str = nr.strftime("%Y-%m-%d %H:%M:%S")

                        # Update schedule state
                        conn.execute("""
                            UPDATE scan_schedules
                            SET last_run    = ?,
                                last_job_id = ?,
                                next_run    = ?
                            WHERE id = ?
                        """, (now_str, job_id, nr_str, s["id"]))

                        log.info("Schedule '%s' → job #%d queued, next run: %s",
                                 s["name"], job_id, nr_str)

                    except Exception as e:
                        log.error("Failed to enqueue job for schedule '%s': %s",
                                  s["name"], e)

        except Exception as e:
            log.exception("Scheduler loop error: %s", e)

        time.sleep(POLL_SECS)


if __name__ == "__main__":
    main()
