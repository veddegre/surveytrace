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

import argparse
import json
import ipaddress
import logging
import os
import resource
import shutil
import sqlite3
import subprocess
import time
from datetime import datetime, timezone, timedelta
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo  # Python < 3.9
from pathlib import Path

from sqlite_pragmas import apply_surveytrace_pragmas
from surveytrace_paths import data_dir, install_root, main_db_path


def process_credential_job_schedules() -> bool:
    """Enqueue credentialed-check runs for due credential_check_jobs (PHP tick, bounded)."""
    script = install_root() / "scripts" / "credential_schedule_tick.php"
    if not script.is_file():
        return True
    php = shutil.which("php") or shutil.which("php8") or shutil.which("php82") or shutil.which("php81")
    if not php:
        log.warning("credential_schedule_tick: no php binary in PATH")
        return False
    try:
        proc = subprocess.run(
            [php, str(script), "--once"],
            cwd=str(install_root()),
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        if proc.returncode != 0:
            log.warning(
                "credential_schedule_tick failed rc=%s stderr=%s",
                proc.returncode,
                (proc.stderr or "")[:500],
            )
            return False
        return True
    except Exception as e:
        log.warning("credential_schedule_tick: %s", e)
        return False

log = logging.getLogger("scheduler")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [scheduler] %(message)s",
)

DB_PATH   = main_db_path()
BACKUP_SCRIPT = Path(__file__).parent / "backup_db.sh"
BACKUP_DIR_DEFAULT = DB_PATH.parent / "backups"
POLL_SECS = 30   # check every 30 seconds

STATUS_PATH = data_dir() / "scheduler_status.json"
_DB_OPEN_FAIL_MAX_CONSECUTIVE = 10
_DB_OPEN_FAIL_MAX_SECONDS = 120

# Zabbix connector SQLite table (single source of truth for scheduler SQL — must be zabbix_connector).
ZABBIX_CONNECTOR_TABLE = "zabbix_connector"

# Log connector "not ready" (disabled / missing creds / schedule off) at INFO only when this changes.
_zabbix_sync_cfg_snap: tuple[bool, bool, bool, bool] | None = None
_zabbix_txn_warned_labels: set[str] = set()


def _clear_stale_scheduler_txn(conn: sqlite3.Connection, label: str) -> None:
    """
    Defensive cleanup before Zabbix lock writes.
    If a transaction is unexpectedly open here, roll it back to avoid nested BEGIN/lock errors.
    """
    if not conn.in_transaction:
        return
    if label not in _zabbix_txn_warned_labels:
        _zabbix_txn_warned_labels.add(label)
        log.warning(
            "rolled back stale scheduler transaction before %s lock",
            label,
        )
    try:
        conn.rollback()
    except Exception as e:
        log.warning("failed rollback before %s lock: %s", label, e)


# ---------------------------------------------------------------------------
# Database helpers + SQLite open diagnostics (parity with collector_ingest_worker)
# ---------------------------------------------------------------------------
def _iso_utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _uid_gid_names() -> tuple[str, str]:
    try:
        import grp
        import pwd

        u = pwd.getpwuid(os.getuid()).pw_name
        g = grp.getgrgid(os.getgid()).gr_name
        return u, g
    except Exception:
        return str(os.getuid()), str(os.getgid())


def _safe_stat_meta(p: Path) -> dict:
    try:
        st = p.stat()
        return {
            "exists": True,
            "mode": oct(st.st_mode),
            "uid": int(st.st_uid),
            "gid": int(st.st_gid),
            "readable": os.access(p, os.R_OK),
            "writable": os.access(p, os.W_OK),
        }
    except OSError:
        return {"exists": False, "mode": None, "uid": None, "gid": None, "readable": False, "writable": False}


def _scheduler_status_write(status: dict) -> None:
    """Atomic JSON write under data/ — must never require DB access."""
    try:
        STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATUS_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(status, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
        tmp.replace(STATUS_PATH)
    except Exception:
        pass


def _scheduler_status_read_previous() -> dict:
    try:
        if STATUS_PATH.is_file():
            parsed = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
            return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}
    return {}


def _is_scheduler_db_open_terminal_failure(exc: BaseException) -> bool:
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    msg = str(exc).lower()
    return "unable to open" in msg or "disk i/o" in msg


def _log_db_open_diagnostics(exc: BaseException | None = None) -> None:
    try:
        dbp = Path(DB_PATH).resolve()
    except Exception:
        dbp = Path(DB_PATH)
    parent = dbp.parent
    uname, gname = _uid_gid_names()
    parent_exists = parent.exists()
    parent_is_dir = parent.is_dir() if parent_exists else False
    parent_rw = os.access(str(parent), os.W_OK) if parent_exists and parent_is_dir else False
    parent_r = os.access(str(parent), os.R_OK) if parent_exists and parent_is_dir else False
    db_exists = dbp.is_file()
    db_rw = os.access(str(dbp), os.R_OK | os.W_OK) if db_exists else False
    db_r = os.access(str(dbp), os.R_OK) if db_exists else False
    wal_meta = _safe_stat_meta(Path(str(dbp) + "-wal"))
    shm_meta = _safe_stat_meta(Path(str(dbp) + "-shm"))
    try:
        sup_groups = sorted(int(g) for g in os.getgroups())
    except OSError:
        sup_groups = []
    try:
        nofile_soft, nofile_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except OSError:
        nofile_soft, nofile_hard = (-1, -1)
    try:
        pmode = oct(parent.stat().st_mode) if parent_exists else "n/a"
    except OSError:
        pmode = "?"
    try:
        fmode = oct(dbp.stat().st_mode) if db_exists else "n/a"
    except OSError:
        fmode = "?"
    err = repr(exc) if exc is not None else ""
    log.error(
        "SQLite open failed | resolved_db_path=%s | install_root=%s | cwd=%s | euid=%s egid=%s (%s:%s) | "
        "parent=%s exists=%s is_dir=%s mode=%s readable=%s writable=%s | "
        "db_file_exists=%s mode=%s db_readable=%s db_writable=%s | "
        "wal=%s shm=%s | supplementary_groups=%s | nofile_soft=%s nofile_hard=%s | "
        "env_INSTALL_DIR=%r env_DB_PATH=%r | err=%s",
        dbp,
        install_root().resolve(),
        os.getcwd(),
        os.geteuid(),
        os.getegid(),
        uname,
        gname,
        parent,
        parent_exists,
        parent_is_dir,
        pmode,
        parent_r,
        parent_rw,
        db_exists,
        fmode,
        db_r,
        db_rw,
        wal_meta,
        shm_meta,
        sup_groups,
        nofile_soft,
        nofile_hard,
        os.environ.get("SURVEYTRACE_INSTALL_DIR"),
        os.environ.get("SURVEYTRACE_DB_PATH"),
        err,
    )


def _preflight_sqlite() -> bool:
    try:
        dbp = Path(DB_PATH).resolve()
    except Exception:
        dbp = Path(DB_PATH)
    parent = dbp.parent
    if not parent.is_dir():
        log.error("preflight: data directory missing or not a directory: %s", parent)
        return False
    if not os.access(str(parent), os.W_OK | os.R_OK):
        log.error("preflight: data directory not readable/writable for this process: %s", parent)
        _log_db_open_diagnostics()
        return False
    try:
        c = sqlite3.connect(str(dbp), timeout=10)
        c.execute("SELECT 1")
        c.close()
    except sqlite3.OperationalError as e:
        log.error("preflight: SQLite connect failed: %s", e)
        _log_db_open_diagnostics(e)
        return False
    return True


def db_conn() -> sqlite3.Connection:
    p = Path(DB_PATH).resolve()
    try:
        conn = sqlite3.connect(str(p), timeout=60)
    except sqlite3.OperationalError as e:
        _log_db_open_diagnostics(e)
        raise
    conn.row_factory = sqlite3.Row
    apply_surveytrace_pragmas(conn)
    return conn


def _run_db_open_check() -> bool:
    """CLI --check-db-open: open DB and read sqlite_master (no writes)."""
    if not _preflight_sqlite():
        return False
    try:
        dbp = Path(DB_PATH).resolve()
    except Exception:
        dbp = Path(DB_PATH)
    try:
        c = sqlite3.connect(str(dbp), timeout=30)
        try:
            c.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")
        finally:
            c.close()
    except sqlite3.OperationalError as e:
        _log_db_open_diagnostics(e)
        return False
    return True


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
        ("schedule_action", "TEXT DEFAULT 'scan'"),
    ]:
        if col not in existing:
            conn.execute(f"ALTER TABLE scan_schedules ADD COLUMN {col} {defn}")

    try:
        job_cols2 = {row[1] for row in conn.execute("PRAGMA table_info(scan_jobs)").fetchall()}
        if "is_baseline" not in job_cols2:
            conn.execute("ALTER TABLE scan_jobs ADD COLUMN is_baseline INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS report_artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            schedule_id INTEGER,
            baseline_job_id INTEGER,
            compare_job_id INTEGER,
            kind TEXT DEFAULT 'scheduled',
            title TEXT,
            payload_json TEXT NOT NULL DEFAULT '{}'
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_report_artifacts_created ON report_artifacts(created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_report_artifacts_schedule ON report_artifacts(schedule_id, id DESC)"
    )

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
    conn.execute(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('zabbix_auto_sync_interval_secs', '900')"
    )
    conn.execute(
        "INSERT OR IGNORE INTO config (key, value) VALUES ('zabbix_output_push_interval_secs', '300')"
    )


def _ensure_zabbix_connector_scheduler_columns(conn: sqlite3.Connection) -> None:
    try:
        n = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            (ZABBIX_CONNECTOR_TABLE,),
        ).fetchone()
        if not n:
            log.warning(
                "SurveyTrace scheduler: SQLite table %r is missing (run PHP / app migrations first); "
                "skipping zabbix_connector scheduler column updates.",
                ZABBIX_CONNECTOR_TABLE,
            )
            return
        cols = {
            row[1]
            for row in conn.execute(f"PRAGMA table_info({ZABBIX_CONNECTOR_TABLE})").fetchall()
        }
        if "scheduled_sync_lock" not in cols:
            conn.execute(
                f"ALTER TABLE {ZABBIX_CONNECTOR_TABLE} ADD COLUMN scheduled_sync_lock INTEGER NOT NULL DEFAULT 0"
            )
        if "scheduled_sync_lock_at" not in cols:
            conn.execute(f"ALTER TABLE {ZABBIX_CONNECTOR_TABLE} ADD COLUMN scheduled_sync_lock_at TEXT")
        if "scheduled_output_lock" not in cols:
            conn.execute(
                f"ALTER TABLE {ZABBIX_CONNECTOR_TABLE} ADD COLUMN scheduled_output_lock INTEGER NOT NULL DEFAULT 0"
            )
        if "scheduled_output_lock_at" not in cols:
            conn.execute(f"ALTER TABLE {ZABBIX_CONNECTOR_TABLE} ADD COLUMN scheduled_output_lock_at TEXT")
        if "output_sender_host" not in cols:
            conn.execute(
                f"ALTER TABLE {ZABBIX_CONNECTOR_TABLE} ADD COLUMN output_sender_host TEXT NOT NULL DEFAULT ''"
            )
        if "output_sender_port" not in cols:
            conn.execute(
                f"ALTER TABLE {ZABBIX_CONNECTOR_TABLE} ADD COLUMN output_sender_port INTEGER NOT NULL DEFAULT 10051"
            )
        if "sync_schedule_enabled" not in cols:
            conn.execute(
                f"ALTER TABLE {ZABBIX_CONNECTOR_TABLE} ADD COLUMN sync_schedule_enabled INTEGER NOT NULL DEFAULT 0"
            )
        if "sync_interval_minutes" not in cols:
            conn.execute(
                f"ALTER TABLE {ZABBIX_CONNECTOR_TABLE} ADD COLUMN sync_interval_minutes INTEGER NOT NULL DEFAULT 60"
            )
        if "next_sync_at" not in cols:
            conn.execute(f"ALTER TABLE {ZABBIX_CONNECTOR_TABLE} ADD COLUMN next_sync_at TEXT")
        if "last_sync_started_at" not in cols:
            conn.execute(f"ALTER TABLE {ZABBIX_CONNECTOR_TABLE} ADD COLUMN last_sync_started_at TEXT")
        if "last_sync_completed_at" not in cols:
            conn.execute(f"ALTER TABLE {ZABBIX_CONNECTOR_TABLE} ADD COLUMN last_sync_completed_at TEXT")
    except sqlite3.OperationalError as e:
        log.warning("zabbix_connector scheduler columns: %s", e)


def maybe_run_zabbix_scheduled_sync(conn: sqlite3.Connection, now: datetime) -> None:
    """Spawn api/zabbix_sync_worker.php when scheduled Zabbix pull is enabled and next_sync_at is due."""
    global _zabbix_sync_cfg_snap
    _ = now  # due check uses SQLite datetime('now') to match stored TEXT timestamps
    root = install_root()
    worker = root / "api" / "zabbix_sync_worker.php"
    worker_path = str(worker)
    if not worker.is_file():
        log.warning(
            "Zabbix scheduled sync: worker script missing, skip (install_root=%s worker=%s)",
            str(root),
            worker_path,
        )
        return
    try:
        _ensure_zabbix_connector_scheduler_columns(conn)
        ztab = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            (ZABBIX_CONNECTOR_TABLE,),
        ).fetchone()
        if not ztab:
            log.warning(
                "Zabbix scheduled sync: table %r missing; skipping scheduled pull.",
                ZABBIX_CONNECTOR_TABLE,
            )
            return
    except Exception as e:
        log.warning("Zabbix scheduled sync: schema check failed: %s", e)
        return

    lock_stale_mod = "-2700 seconds"
    php_bin = (os.environ.get("SURVEYTRACE_PHP_BIN") or os.environ.get("SURVEYTRACE_PHP_CLI") or "php").strip() or "php"

    row = None
    try:
        row = conn.execute(
            f"""
            SELECT enabled, api_url, api_token, sync_schedule_enabled, next_sync_at,
                   COALESCE(scheduled_sync_lock, 0) AS scheduled_sync_lock,
                   scheduled_sync_lock_at,
                   (next_sync_at IS NULL OR TRIM(COALESCE(next_sync_at, '')) = ''
                    OR next_sync_at <= datetime('now')) AS sync_due,
                   (COALESCE(scheduled_sync_lock, 0) = 0 OR scheduled_sync_lock_at IS NULL
                    OR datetime(scheduled_sync_lock_at) < datetime('now', ?)) AS lock_ok
            FROM {ZABBIX_CONNECTOR_TABLE}
            WHERE id = 1
            """,
            (lock_stale_mod,),
        ).fetchone()
    except Exception as e:
        log.warning("Zabbix scheduled sync: could not read connector row: %s", e)
        return

    if row is None:
        log.debug("Zabbix scheduled sync: no connector row id=1, skip")
        return

    enabled = int(row["enabled"] or 0)
    api_url = (row["api_url"] or "").strip()
    api_token = (row["api_token"] or "").strip()
    sync_schedule_enabled = int(row["sync_schedule_enabled"] or 0)
    next_sync_at = row["next_sync_at"]
    sync_due = int(row["sync_due"] or 0)
    lock_ok = int(row["lock_ok"] or 0)
    lock_val = int(row["scheduled_sync_lock"] or 0)
    lock_at = row["scheduled_sync_lock_at"]

    cfg_snap = (
        enabled == 1,
        bool(api_url),
        bool(api_token),
        sync_schedule_enabled == 1,
    )
    if not all(cfg_snap):
        if cfg_snap != _zabbix_sync_cfg_snap:
            _zabbix_sync_cfg_snap = cfg_snap
            parts = []
            if enabled != 1:
                parts.append("enabled=0")
            if not api_url:
                parts.append("api_url empty")
            if not api_token:
                parts.append("api_token missing")
            if sync_schedule_enabled != 1:
                parts.append("sync_schedule_enabled off")
            log.info(
                "Zabbix scheduled sync: not ready (%s), skip",
                ", ".join(parts) or "unknown",
            )
        return
    _zabbix_sync_cfg_snap = (True, True, True, True)

    if not sync_due:
        log.debug(
            "Zabbix scheduled sync: next_sync_at not due (next_sync_at=%r), skip",
            next_sync_at,
        )
        return
    if not lock_ok:
        log.debug(
            "Zabbix scheduled sync: lock already active (scheduled_sync_lock=%s scheduled_sync_lock_at=%r), skip",
            lock_val,
            lock_at,
        )
        return

    log.info(
        "Zabbix scheduled sync: due (next_sync_at=%r), acquiring lock",
        next_sync_at,
    )

    try:
        _clear_stale_scheduler_txn(conn, "Zabbix scheduled sync")
        cur = conn.execute(
            f"""UPDATE {ZABBIX_CONNECTOR_TABLE} SET scheduled_sync_lock=1, scheduled_sync_lock_at=datetime('now')
                WHERE id=1 AND enabled=1
                  AND COALESCE(sync_schedule_enabled,0)=1
                  AND TRIM(COALESCE(api_url,''))!='' AND TRIM(COALESCE(api_token,''))!=''
                  AND (COALESCE(scheduled_sync_lock,0)=0 OR scheduled_sync_lock_at IS NULL
                       OR datetime(scheduled_sync_lock_at) < datetime('now', ?))
                  AND (next_sync_at IS NULL OR TRIM(COALESCE(next_sync_at,''))=''
                       OR next_sync_at <= datetime('now'))""",
            (lock_stale_mod,),
        ).rowcount
        if cur != 1:
            conn.rollback()
            log.debug(
                "Zabbix scheduled sync: lock UPDATE matched %s rows (racy skip or row changed), skip",
                cur,
            )
            return
        conn.commit()
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        log.warning("Zabbix scheduled sync: lock/update failed: %s", e)
        return

    log.info("Zabbix scheduled sync: lock acquired (id=1)")
    try:
        proc = subprocess.Popen(
            [php_bin, worker_path],
            cwd=str(root),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        log.info(
            "Zabbix scheduled sync: worker spawned pid=%s php=%s worker=%s cwd=%s",
            proc.pid,
            php_bin,
            worker_path,
            str(root),
        )
    except Exception as e:
        log.error(
            "Zabbix scheduled sync: spawn failed: %s (php=%s worker=%s cwd=%s)",
            e,
            php_bin,
            worker_path,
            str(root),
        )
        try:
            c2 = db_conn()
            try:
                c2.execute(
                    f"UPDATE {ZABBIX_CONNECTOR_TABLE} SET scheduled_sync_lock=0, scheduled_sync_lock_at=NULL "
                    "WHERE id=1"
                )
                c2.commit()
            finally:
                c2.close()
        except Exception:
            pass


def maybe_run_zabbix_output_push(conn: sqlite3.Connection, now: datetime) -> None:
    """Spawn api/zabbix_output_worker.php when output is enabled and due."""
    root = install_root()
    worker = root / "api" / "zabbix_output_worker.php"
    if not worker.is_file():
        log.warning(
            "Zabbix output push: worker script missing, skip (install_root=%s worker=%s)",
            str(root),
            str(worker),
        )
        return
    try:
        _ensure_zabbix_connector_scheduler_columns(conn)
        ztab = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
            (ZABBIX_CONNECTOR_TABLE,),
        ).fetchone()
        if not ztab:
            log.warning(
                "Zabbix output push: table %r missing; skipping scheduled output.",
                ZABBIX_CONNECTOR_TABLE,
            )
            return
    except Exception as e:
        log.warning("Zabbix output push: schema check failed: %s", e)
        return
    try:
        interval = int(_cfg_get(conn, "zabbix_output_push_interval_secs", "300") or "300")
    except Exception:
        interval = 300
    interval = max(120, min(3600, interval))
    push_age_mod = f"-{interval} seconds"
    lock_stale_mod = "-1800 seconds"
    php_bin = (os.environ.get("SURVEYTRACE_PHP_BIN") or os.environ.get("SURVEYTRACE_PHP_CLI") or "php").strip() or "php"
    row = None
    try:
        row = conn.execute(
            f"""
            SELECT enabled, output_enabled, api_url, api_token, output_host,
                   COALESCE(scheduled_output_lock, 0) AS scheduled_output_lock,
                   scheduled_output_lock_at,
                   last_output_push_at,
                   (last_output_push_at IS NULL OR TRIM(COALESCE(last_output_push_at,''))=''
                    OR datetime(last_output_push_at) <= datetime('now', ?)) AS output_due,
                   (COALESCE(scheduled_output_lock,0)=0 OR scheduled_output_lock_at IS NULL
                    OR datetime(scheduled_output_lock_at) < datetime('now', ?)) AS lock_ok
            FROM {ZABBIX_CONNECTOR_TABLE}
            WHERE id = 1
            """,
            (push_age_mod, lock_stale_mod),
        ).fetchone()
    except Exception as e:
        log.warning("Zabbix output push: could not read connector row: %s", e)
        return
    if row is None:
        log.debug("Zabbix output push: no connector row id=1, skip")
        return
    output_due = int(row["output_due"] or 0)
    lock_ok = int(row["lock_ok"] or 0)
    if not output_due:
        log.debug(
            "Zabbix output push: not due (last_output_push_at=%r), skip",
            row["last_output_push_at"],
        )
        return
    if not lock_ok:
        log.debug(
            "Zabbix output push: lock already active (scheduled_output_lock=%s scheduled_output_lock_at=%r), skip",
            int(row["scheduled_output_lock"] or 0),
            row["scheduled_output_lock_at"],
        )
        return
    log.info(
        "Zabbix output push: due (last_output_push_at=%r), acquiring lock",
        row["last_output_push_at"],
    )
    try:
        _clear_stale_scheduler_txn(conn, "Zabbix output push")
        cur = conn.execute(
            f"""UPDATE {ZABBIX_CONNECTOR_TABLE} SET scheduled_output_lock=1, scheduled_output_lock_at=datetime('now')
                WHERE id=1
                  AND enabled=1
                  AND COALESCE(output_enabled,0)=1
                  AND TRIM(COALESCE(api_url,''))!=''
                  AND TRIM(COALESCE(api_token,''))!=''
                  AND TRIM(COALESCE(output_host,''))!=''
                  AND (COALESCE(scheduled_output_lock,0)=0 OR scheduled_output_lock_at IS NULL
                       OR datetime(scheduled_output_lock_at) < datetime('now', ?))
                  AND (last_output_push_at IS NULL OR TRIM(COALESCE(last_output_push_at,''))=''
                       OR datetime(last_output_push_at) <= datetime('now', ?))""",
            (lock_stale_mod, push_age_mod),
        ).rowcount
        if cur != 1:
            conn.rollback()
            log.debug("Zabbix output push: not due or gates failed (UPDATE matched 0 rows), skip")
            return
        conn.commit()
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        log.warning("Zabbix output push: lock/update failed: %s", e)
        return
    log.info("Zabbix output push: lock acquired (id=1)")
    try:
        proc = subprocess.Popen(
            [php_bin, str(worker)],
            cwd=str(root),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        log.info(
            "Zabbix output push: spawned worker (interval=%ss) pid=%s worker=%s",
            interval,
            proc.pid,
            str(worker),
        )
    except Exception as e:
        log.error("Zabbix output push: spawn failed: %s", e)
        try:
            c2 = db_conn()
            try:
                c2.execute(
                    f"UPDATE {ZABBIX_CONNECTOR_TABLE} SET scheduled_output_lock=0, scheduled_output_lock_at=NULL "
                    "WHERE id=1"
                )
                c2.commit()
            finally:
                c2.close()
        except Exception:
            pass
        return


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
    collector_id = int(schedule.get("collector_id") or 0)
    if collector_id > 0:
        row = conn.execute("SELECT allowed_cidrs_json FROM collectors WHERE id=? LIMIT 1", (collector_id,)).fetchone()
        allow = []
        if row:
            try:
                raw = row["allowed_cidrs_json"] if isinstance(row, sqlite3.Row) else row[0]
                parsed = json.loads(raw or "[]")
                if isinstance(parsed, list):
                    allow = [str(x).strip() for x in parsed if str(x).strip()]
            except Exception:
                allow = []
        if allow:
            target_parts = [p.strip() for p in str(schedule["target_cidr"]).replace("\n", ",").split(",") if p.strip()]
            for t in target_parts:
                try:
                    tnet = ipaddress.ip_network(t, strict=False)
                except Exception:
                    raise RuntimeError(f"schedule target invalid for collector policy: {t}")
                ok = False
                for a in allow:
                    try:
                        anet = ipaddress.ip_network(a, strict=False)
                    except Exception:
                        continue
                    if tnet.overlaps(anet):
                        ok = True
                        break
                if not ok:
                    raise RuntimeError(f"target outside collector allowlist: {t}")
    enr_ids = schedule.get("enrichment_source_ids")
    prof = str(schedule.get("profile") or "standard_inventory").strip()
    if prof == "fast_full_tcp":
        prof = "full_tcp"
    try:
        sched_scope_i = int(schedule.get("scope_id") or 0)
    except (TypeError, ValueError):
        sched_scope_i = 0
    if sched_scope_i < 0:
        sched_scope_i = 0
    scope_bind = sched_scope_i if sched_scope_i > 0 else None
    conn.execute("""
        INSERT INTO scan_jobs
            (target_cidr, label, exclusions, phases, rate_pps, inter_delay,
             scan_mode, profile, priority, schedule_id, collector_id, created_by, enrichment_source_ids, scope_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'scheduler', ?, ?)
    """, (
        schedule["target_cidr"],
        label,
        schedule["exclusions"] or "",
        schedule["phases"] or '["passive","icmp","banner","fingerprint","cve"]',
        schedule["rate_pps"] or 5,
        schedule["inter_delay"] or 200,
        schedule["scan_mode"] or "auto",
        prof,
        schedule["priority"] or 20,
        schedule["id"],
        collector_id,
        enr_ids,
        scope_bind,
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


def _materialize_scheduled_report(conn: sqlite3.Connection, schedule_id: int) -> None:
    """Run api/reporting_cli.php materialize <schedule_id>."""
    root = Path(__file__).resolve().parent.parent
    php_bin = os.environ.get("SURVEYTRACE_PHP_BIN", "php")
    script = root / "api" / "reporting_cli.php"
    if not script.is_file():
        log.error("reporting_cli.php missing at %s", script)
        return
    try:
        r = subprocess.run(
            [php_bin, str(script), "materialize", str(schedule_id)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if r.returncode != 0:
            log.error(
                "Scheduled report failed schedule_id=%s rc=%s err=%s out=%s",
                schedule_id,
                r.returncode,
                (r.stderr or "")[:500],
                (r.stdout or "")[:500],
            )
        else:
            # reporting_cli.php prints one JSON line on success; parse first non-empty line only.
            payload = None
            line = ""
            for ln in (r.stdout or "").splitlines():
                s = ln.strip()
                if s:
                    line = s
                    break
            if line:
                try:
                    payload = json.loads(line)
                except ValueError:
                    log.warning(
                        "Scheduled report stdout is not valid JSON schedule_id=%s snippet=%s",
                        schedule_id,
                        line[:500],
                    )
            if isinstance(payload, dict) and payload.get("ok") is True:
                log.info(
                    "Scheduled report OK schedule_id=%s artifact_id=%s duration_ms=%s",
                    payload.get("schedule_id", schedule_id),
                    payload.get("artifact_id"),
                    payload.get("duration_ms"),
                )
            else:
                log.info("Scheduled report OK schedule_id=%s", schedule_id)
            if r.stderr and r.stderr.strip():
                log.warning(
                    "Scheduled report stderr schedule_id=%s: %s",
                    schedule_id,
                    r.stderr.strip()[:500],
                )
    except Exception as e:
        log.error("Scheduled report subprocess schedule_id=%s: %s", schedule_id, e)


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

    action = (s.get("schedule_action") or "scan").strip().lower()
    if action == "report":
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
                "Schedule '%s' (id=%d) report — skip_no_run: advancing next_run to %s",
                s["name"],
                s["id"],
                nr_str,
            )
            return
        if policy == "run_all":
            log.warning(
                "Schedule '%s' (id=%d): run_all with schedule_action=report — emitting one report",
                s["name"],
                s["id"],
            )
        _materialize_scheduled_report(conn, int(s["id"]))
        conn.execute(
            """
            UPDATE scan_schedules
            SET last_run = ?, last_job_id = 0, next_run = ?
            WHERE id = ?
            """,
            (now_str, nr_str, s["id"]),
        )
        log.info("Schedule '%s' (report) next_run: %s", s["name"], nr_str)
        return

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
    try:
        nr0 = _parse_utc_naive(str(s.get("next_run") or ""))
        overdue_sec = max(0, int((now - nr0).total_seconds()))
    except Exception:
        overdue_sec = 0
    if overdue_sec > 300:
        log.info(
            "Schedule '%s' (id=%d) was overdue by ~%d min; run_once catch-up (single job, no backlog storm)",
            s["name"],
            s["id"],
            overdue_sec // 60,
        )
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


def seed_missing_next_runs(conn: sqlite3.Connection, now: datetime) -> None:
    """
    Ensure enabled/unpaused schedules always have next_run populated from cron/timezone.
    Needed for schedules created while scheduler_daemon is already running.
    """
    schedules = conn.execute(
        """
        SELECT * FROM scan_schedules
        WHERE enabled = 1 AND COALESCE(paused, 0) = 0 AND next_run IS NULL
        """
    ).fetchall()
    for s in schedules:
        try:
            nr = next_cron_run(s["cron_expr"], now, s.get("timezone") or "UTC")
            conn.execute(
                "UPDATE scan_schedules SET next_run=? WHERE id=?",
                (nr.strftime("%Y-%m-%d %H:%M:%S"), s["id"]),
            )
            log.info(
                "Seeded next_run id=%s collector_id=%s cron=%s tz=%s -> %s (%s)",
                s.get("id"),
                s.get("collector_id"),
                s.get("cron_expr"),
                s.get("timezone") or "UTC",
                nr.strftime("%Y-%m-%d %H:%M:%S"),
                s["name"],
            )
        except Exception as e:
            log.warning("Could not compute next_run for schedule '%s': %s", s["name"], e)


# ---------------------------------------------------------------------------
# Main scheduler loop
# ---------------------------------------------------------------------------
def _parse_cli_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="SurveyTrace scheduler daemon")
    ap.add_argument(
        "--check-db-open",
        action="store_true",
        help="Verify data dir + SQLite open + sqlite_master read then exit 0/1 (no scheduler loop)",
    )
    return ap.parse_args()


def main() -> None:
    args = _parse_cli_args()
    prev = _scheduler_status_read_previous()
    st: dict = {
        "pid": os.getpid(),
        "last_start_utc": _iso_utc_now(),
        "last_loop_success_utc": str(prev.get("last_loop_success_utc") or ""),
        "last_db_open_success_utc": str(prev.get("last_db_open_success_utc") or ""),
        "last_schedule_scan_attempt_utc": str(prev.get("last_schedule_scan_attempt_utc") or ""),
        "last_credential_schedule_tick_utc": str(prev.get("last_credential_schedule_tick_utc") or ""),
        "db_open_consecutive_failures": 0,
        "db_open_first_failure_utc": "",
        "last_db_open_error": "",
        "updated_at": _iso_utc_now(),
    }
    _scheduler_status_write(st)

    if args.check_db_open:
        ok = _run_db_open_check()
        st["updated_at"] = _iso_utc_now()
        if ok:
            st["last_db_open_success_utc"] = st["updated_at"]
            st["last_db_open_error"] = ""
            st["db_open_consecutive_failures"] = 0
            st["db_open_first_failure_utc"] = ""
            _scheduler_status_write(st)
            log.info("scheduler DB open check: OK")
            raise SystemExit(0)
        st["last_db_open_error"] = "check_db_open_failed"
        st["db_open_consecutive_failures"] = 1
        st["db_open_first_failure_utc"] = st["updated_at"]
        _scheduler_status_write(st)
        log.error("scheduler DB open check: FAILED")
        raise SystemExit(1)

    log.info("SurveyTrace scheduler daemon starting (db: %s)", DB_PATH)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    while not _preflight_sqlite():
        log.error(
            "scheduler preflight failed; fix permissions or SURVEYTRACE_INSTALL_DIR/SURVEYTRACE_DB_PATH; retry in 30s"
        )
        st["last_db_open_error"] = "preflight_failed"
        st["updated_at"] = _iso_utc_now()
        _scheduler_status_write(st)
        time.sleep(30)

    try:
        with db_conn() as conn:
            ensure_schema(conn)
            now0 = datetime.now(timezone.utc).replace(tzinfo=None)
            seed_missing_next_runs(conn, now0)
    except Exception as e:
        log.error("scheduler bootstrap failed: %s", e)
        st["last_db_open_error"] = str(e)[:500]
        st["updated_at"] = _iso_utc_now()
        _scheduler_status_write(st)
        raise SystemExit(2) from e

    st["last_db_open_success_utc"] = _iso_utc_now()
    st["last_db_open_error"] = ""
    st["db_open_consecutive_failures"] = 0
    st["db_open_first_failure_utc"] = ""
    st["updated_at"] = _iso_utc_now()
    _scheduler_status_write(st)

    log.info("Scheduler ready — polling every %ds", POLL_SECS)

    db_open_fail_consecutive = 0
    db_open_fail_window_started_monotonic = 0.0
    non_db_error_count = 0

    while True:
        try:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            now_str = now.strftime("%Y-%m-%d %H:%M:%S")

            with db_conn() as conn:
                purge_expired_trashed_scans(conn)
                maybe_run_db_backup(conn, now)
                if conn.in_transaction:
                    conn.commit()
                maybe_run_zabbix_scheduled_sync(conn, now)
                if conn.in_transaction:
                    conn.commit()
                maybe_run_zabbix_output_push(conn, now)
                if conn.in_transaction:
                    conn.commit()
                seed_missing_next_runs(conn, now)
                due = conn.execute(
                    """
                    SELECT * FROM scan_schedules
                    WHERE enabled = 1
                      AND COALESCE(paused, 0) = 0
                      AND next_run IS NOT NULL
                      AND next_run <= ?
                    ORDER BY next_run ASC
                    """,
                    (now_str,),
                ).fetchall()

                for schedule in due:
                    s = dict(schedule)
                    log.info(
                        "Schedule '%s' (id=%d) is due — policy=%s",
                        s["name"],
                        s["id"],
                        (s.get("missed_run_policy") or "run_once"),
                    )

                    try:
                        process_due_schedule(conn, schedule, now)
                    except Exception as e:
                        log.error("Failed to enqueue job for schedule '%s': %s", s["name"], e)

            ts_ok = _iso_utc_now()
            st["last_db_open_success_utc"] = ts_ok
            st["last_loop_success_utc"] = ts_ok
            st["last_schedule_scan_attempt_utc"] = ts_ok
            st["last_db_open_error"] = ""
            st["db_open_consecutive_failures"] = 0
            st["db_open_first_failure_utc"] = ""
            st["updated_at"] = ts_ok
            db_open_fail_consecutive = 0
            db_open_fail_window_started_monotonic = 0.0
            non_db_error_count = 0
            _scheduler_status_write(st)

            if process_credential_job_schedules():
                st["last_credential_schedule_tick_utc"] = _iso_utc_now()
                st["updated_at"] = st["last_credential_schedule_tick_utc"]
                _scheduler_status_write(st)

        except sqlite3.OperationalError as e:
            if _is_scheduler_db_open_terminal_failure(e):
                db_open_fail_consecutive += 1
                if db_open_fail_window_started_monotonic <= 0.0:
                    db_open_fail_window_started_monotonic = time.monotonic()
                    st["db_open_first_failure_utc"] = _iso_utc_now()
                elapsed_unavailable = max(0.0, time.monotonic() - db_open_fail_window_started_monotonic)
                st["last_db_open_error"] = str(e)[:500]
                st["db_open_consecutive_failures"] = db_open_fail_consecutive
                st["updated_at"] = _iso_utc_now()
                _scheduler_status_write(st)
                should_exit = db_open_fail_consecutive >= _DB_OPEN_FAIL_MAX_CONSECUTIVE or elapsed_unavailable >= float(
                    _DB_OPEN_FAIL_MAX_SECONDS
                )
                if should_exit:
                    msg = (
                        f"SQLite DB unavailable after {db_open_fail_consecutive} attempts / "
                        f"{int(elapsed_unavailable)} seconds; exiting for systemd restart"
                    )
                    log.error(msg)
                    st["last_db_open_error"] = msg
                    st["updated_at"] = _iso_utc_now()
                    _scheduler_status_write(st)
                    raise SystemExit(2)
                if db_open_fail_consecutive <= 3:
                    _log_db_open_diagnostics(e)
                    log.error(
                        "Scheduler DB unavailable; retrying (%s/%s, elapsed=%ss/%ss): %s",
                        db_open_fail_consecutive,
                        _DB_OPEN_FAIL_MAX_CONSECUTIVE,
                        int(elapsed_unavailable),
                        _DB_OPEN_FAIL_MAX_SECONDS,
                        e,
                    )
                elif db_open_fail_consecutive % 5 == 0:
                    log.warning(
                        "Scheduler DB unavailable; retrying (%s/%s, elapsed=%ss/%ss)",
                        db_open_fail_consecutive,
                        _DB_OPEN_FAIL_MAX_CONSECUTIVE,
                        int(elapsed_unavailable),
                        _DB_OPEN_FAIL_MAX_SECONDS,
                    )
            else:
                log.warning("Scheduler sqlite operational error: %s", e)
        except Exception as e:
            non_db_error_count += 1
            if non_db_error_count <= 3:
                log.exception("Scheduler loop error: %s", e)
            else:
                log.error("Scheduler loop error (suppressing traceback after %s repeats): %s", non_db_error_count, e)

        time.sleep(POLL_SECS)


if __name__ == "__main__":
    main()
