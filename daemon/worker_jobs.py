"""
SurveyTrace — worker execution substrate helpers (MVP slice 2).

Lightweight sqlite3 primitives for daemon-side use. No polling loops; callers
open the DB connection and pass it in. Production daemons do not import this yet.
Each helper that mutates data ends with COMMIT (short transactions); avoid wrapping
the same connection in a larger transaction unless you accept intermediate commits.

Structured error_code values match docs/WORKER_EXECUTION_SUBSTRATE.md §6.

@see docs/WORKER_EXECUTION_SUBSTRATE.md
@see docs/WORKER_EXECUTION_MVP_PLAN.md
"""

from __future__ import annotations

import json
import secrets
import sqlite3
from typing import Any, Mapping, Optional, Sequence

WORKER_ERROR_CODES: tuple[str, ...] = (
    "transport_error",
    "auth_error",
    "timeout",
    "policy_blocked",
    "validation_error",
    "dependency_missing",
    "storage_error",
    "internal_error",
)


def error_code_valid(code: Optional[str]) -> bool:
    return bool(code) and code in WORKER_ERROR_CODES


def _json_dumps(value: Optional[Mapping[str, Any]]) -> Optional[str]:
    if value is None or len(value) == 0:
        return None
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return None


def _safe_message(msg: Optional[str], max_len: int = 2000) -> str:
    if msg is None:
        return ""
    s = msg.strip()
    if len(s) > max_len:
        return s[:max_len]
    return s


def _fetchone_dict(cur: sqlite3.Cursor) -> Optional[dict[str, Any]]:
    row = cur.fetchone()
    if not row or not cur.description:
        return None
    cols = [d[0] for d in cur.description]
    return dict(zip(cols, row))


def tables_ready(conn: sqlite3.Connection) -> bool:
    try:
        row = conn.execute(
            "SELECT value FROM config WHERE key = 'migration_worker_execution_substrate_v1' LIMIT 1"
        ).fetchone()
        if not row or str(row[0]) != "1":
            return False
        row2 = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'worker_jobs' LIMIT 1"
        ).fetchone()
        return row2 is not None
    except sqlite3.Error:
        return False


def register_node(
    conn: sqlite3.Connection,
    *,
    node_key: str,
    hostname: Optional[str] = None,
    role: Optional[str] = None,
    status: str = "starting",
    meta_json: Optional[Mapping[str, Any]] = None,
) -> int:
    if not tables_ready(conn):
        return 0
    key = (node_key or "").strip()
    if not key:
        return 0
    host = (hostname or "").strip() or None
    r = (role or "").strip() or None
    st = (status or "").strip() or "starting"
    meta = _json_dumps(dict(meta_json) if meta_json else None)
    try:
        conn.execute(
            """INSERT INTO worker_nodes (node_key, hostname, role, status, meta_json, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
               ON CONFLICT(node_key) DO UPDATE SET
                 hostname = excluded.hostname,
                 role = excluded.role,
                 status = excluded.status,
                 meta_json = excluded.meta_json,
                 updated_at = datetime('now')""",
            (key, host, r, st, meta),
        )
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        return 0
    cur = conn.execute("SELECT id FROM worker_nodes WHERE node_key = ? LIMIT 1", (key,))
    row = cur.fetchone()
    return int(row[0]) if row and row[0] else 0


def heartbeat(
    conn: sqlite3.Connection,
    *,
    node_id: int,
    worker_type: str,
    worker_key: Optional[str] = None,
    status: str = "healthy",
    details_json: Optional[Mapping[str, Any]] = None,
) -> None:
    if not tables_ready(conn) or node_id < 1:
        return
    wtype = (worker_type or "").strip()
    if not wtype:
        return
    st = (status or "").strip() or "healthy"
    wk = (worker_key or "").strip() or None
    det = _json_dumps(dict(details_json) if details_json else None)
    try:
        conn.execute(
            """INSERT INTO worker_heartbeats (node_id, worker_key, worker_type, status, heartbeat_at, details_json)
               VALUES (?, ?, ?, ?, datetime('now'), ?)""",
            (node_id, wk, wtype, st, det),
        )
        conn.execute("UPDATE worker_nodes SET updated_at = datetime('now') WHERE id = ?", (node_id,))
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass


def enqueue_job(
    conn: sqlite3.Connection,
    *,
    job_type: str,
    entity_type: Optional[str] = None,
    entity_id: Optional[int] = None,
    priority: int = 0,
    max_attempts: int = 3,
    payload_json: Optional[Mapping[str, Any]] = None,
) -> int:
    if not tables_ready(conn):
        return 0
    jt = (job_type or "").strip()
    if not jt:
        return 0
    et = (entity_type or "").strip() or None
    eid = int(entity_id) if entity_id is not None else None
    mx = max(1, int(max_attempts))
    payload = _json_dumps(dict(payload_json) if payload_json else None)
    try:
        cur = conn.execute(
            """INSERT INTO worker_jobs (job_type, entity_type, entity_id, status, priority, max_attempts, payload_json, created_at, updated_at)
               VALUES (?, ?, ?, 'queued', ?, ?, ?, datetime('now'), datetime('now'))""",
            (jt, et, eid, int(priority), mx, payload),
        )
        conn.commit()
        return int(cur.lastrowid) if cur.lastrowid else 0
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        return 0


def lease_next_job(
    conn: sqlite3.Connection,
    *,
    lease_node_id: int,
    lease_token: Optional[str] = None,
    lease_ttl_sec: int = 300,
    allowed_job_types: Optional[Sequence[str]] = None,
) -> Optional[dict[str, Any]]:
    if not tables_ready(conn) or lease_node_id < 1:
        return None
    token = (lease_token or "").strip() or secrets.token_hex(16)
    ttl = max(30, min(86400, int(lease_ttl_sec)))
    mod = f"+{ttl} seconds"
    allowed = [str(t).strip() for t in (allowed_job_types or ()) if str(t).strip()]
    cur = conn.cursor()
    try:
        cur.execute("BEGIN IMMEDIATE")
        sql = """SELECT id FROM worker_jobs WHERE status = 'queued'
            AND cancel_requested_at IS NULL
            AND (next_attempt_at IS NULL OR datetime(next_attempt_at) <= datetime('now'))"""
        params: list[Any] = []
        if allowed:
            ph = ",".join("?" * len(allowed))
            sql += f" AND job_type IN ({ph})"
            params.extend(allowed)
        sql += " ORDER BY priority DESC, id ASC LIMIT 1"
        cur.execute(sql, params)
        row = cur.fetchone()
        if not row:
            conn.commit()
            return None
        jid = int(row[0])
        cur.execute(
            """UPDATE worker_jobs SET status = 'leased', lease_node_id = ?, lease_token = ?, leased_at = datetime('now'),
                lease_expires_at = datetime('now', ?), updated_at = datetime('now')
             WHERE id = ? AND status = 'queued'""",
            (lease_node_id, token, mod, jid),
        )
        if cur.rowcount != 1:
            conn.rollback()
            return None
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        return None
    cur2 = conn.execute("SELECT * FROM worker_jobs WHERE id = ? LIMIT 1", (jid,))
    return _fetchone_dict(cur2)


def start_attempt(conn: sqlite3.Connection, job_id: int, *, node_id: Optional[int] = None) -> int:
    if not tables_ready(conn) or job_id < 1:
        return 0
    nid = int(node_id) if node_id is not None and int(node_id) >= 1 else None
    cur = conn.cursor()
    try:
        cur.execute("BEGIN IMMEDIATE")
        cur.execute(
            "SELECT id, status, cancel_requested_at FROM worker_jobs WHERE id = ? LIMIT 1",
            (job_id,),
        )
        chk = _fetchone_dict(cur)
        if not chk:
            conn.rollback()
            return 0
        st = str(chk.get("status") or "")
        if st in ("cancelled", "completed", "failed"):
            conn.rollback()
            return 0
        creq = chk.get("cancel_requested_at")
        if creq is not None and str(creq).strip() != "":
            conn.rollback()
            return 0
        cur.execute(
            """INSERT INTO worker_job_attempts (job_id, attempt_no, node_id, status, started_at)
               SELECT ?, COALESCE(MAX(attempt_no), 0) + 1, ?, 'running', datetime('now')
               FROM worker_job_attempts WHERE job_id = ?""",
            (job_id, nid, job_id),
        )
        aid = cur.lastrowid
        if not aid:
            conn.rollback()
            return 0
        cur.execute(
            """UPDATE worker_jobs SET status = 'running', attempts = (SELECT MAX(attempt_no) FROM worker_job_attempts WHERE job_id = ?),
                updated_at = datetime('now') WHERE id = ?""",
            (job_id, job_id),
        )
        conn.commit()
        return int(aid)
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        return 0


def finish_attempt(
    conn: sqlite3.Connection,
    attempt_id: int,
    *,
    status: str = "completed",
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
    metrics_json: Optional[Mapping[str, Any]] = None,
) -> None:
    if not tables_ready(conn) or attempt_id < 1:
        return
    st = (status or "").strip() or "completed"
    ec = (error_code or "").strip() or None
    if ec and not error_code_valid(ec):
        ec = "internal_error"
    em = _safe_message(error_message) if error_message else None
    met = _json_dumps(dict(metrics_json) if metrics_json else None)
    try:
        conn.execute(
            """UPDATE worker_job_attempts SET status = ?, finished_at = datetime('now'), error_code = ?, error_message = ?, metrics_json = ?
             WHERE id = ?""",
            (st, ec, em or None, met, attempt_id),
        )
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass


def finish_job(
    conn: sqlite3.Connection,
    job_id: int,
    *,
    result_summary_json: Optional[Mapping[str, Any]] = None,
) -> None:
    if not tables_ready(conn) or job_id < 1:
        return
    sm = _json_dumps(dict(result_summary_json) if result_summary_json else None)
    try:
        conn.execute(
            """UPDATE worker_jobs SET status = 'completed', finished_at = datetime('now'), updated_at = datetime('now'),
                lease_node_id = NULL, lease_token = NULL, leased_at = NULL, lease_expires_at = NULL,
                result_summary_json = COALESCE(?, result_summary_json), error_code = NULL, error_message = NULL
             WHERE id = ?""",
            (sm, job_id),
        )
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass


def fail_job(
    conn: sqlite3.Connection,
    job_id: int,
    *,
    error_code: str = "internal_error",
    error_message: Optional[str] = None,
) -> None:
    if not tables_ready(conn) or job_id < 1:
        return
    ec = (error_code or "").strip() or "internal_error"
    if not error_code_valid(ec):
        ec = "internal_error"
    em = _safe_message(error_message) if error_message else ""
    try:
        conn.execute(
            """UPDATE worker_jobs SET status = 'failed', finished_at = datetime('now'), updated_at = datetime('now'),
                error_code = ?, error_message = ?,
                lease_node_id = NULL, lease_token = NULL, leased_at = NULL, lease_expires_at = NULL
             WHERE id = ?""",
            (ec, em, job_id),
        )
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass


def request_cancel(conn: sqlite3.Connection, job_id: int, actor: str) -> None:
    if not tables_ready(conn) or job_id < 1:
        return
    act = _safe_message(actor, 512)
    try:
        cur = conn.execute(
            """UPDATE worker_jobs SET cancel_requested_at = datetime('now'), updated_at = datetime('now')
               WHERE id = ? AND finished_at IS NULL""",
            (job_id,),
        )
        if cur.rowcount < 1:
            conn.commit()
            return
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        return
    log_event(
        conn,
        job_id=job_id,
        event_type="cancel_requested",
        level="info",
        message="Cancellation requested",
        details_json={"actor": act},
    )


def finalize_queued_cancel(conn: sqlite3.Connection, job_id: int) -> bool:
    """Terminal cancel for queued+cancel_requested rows (see st_worker_finalize_queued_cancel in PHP)."""
    if not tables_ready(conn) or job_id < 1:
        return False
    try:
        cur = conn.execute(
            """UPDATE worker_jobs SET status = 'cancelled', finished_at = datetime('now'), updated_at = datetime('now'),
                lease_node_id = NULL, lease_token = NULL, leased_at = NULL, lease_expires_at = NULL,
                error_code = NULL, error_message = NULL
             WHERE id = ? AND status = 'queued' AND cancel_requested_at IS NOT NULL AND finished_at IS NULL""",
            (job_id,),
        )
        conn.commit()
        return cur.rowcount == 1
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        return False


def finish_job_cancelled(
    conn: sqlite3.Connection,
    job_id: int,
    *,
    result_summary_json: Optional[Mapping[str, Any]] = None,
) -> None:
    if not tables_ready(conn) or job_id < 1:
        return
    sm = _json_dumps(dict(result_summary_json) if result_summary_json else None)
    try:
        conn.execute(
            """UPDATE worker_jobs SET status = 'cancelled', finished_at = datetime('now'), updated_at = datetime('now'),
                lease_node_id = NULL, lease_token = NULL, leased_at = NULL, lease_expires_at = NULL,
                result_summary_json = COALESCE(?, result_summary_json), error_code = NULL, error_message = NULL
             WHERE id = ? AND finished_at IS NULL""",
            (sm, job_id),
        )
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass


def finalize_leased_cancel(conn: sqlite3.Connection, job_id: int) -> bool:
    """Promote leased+cancel_requested to cancelled (worker could not start_attempt)."""
    if not tables_ready(conn) or job_id < 1:
        return False
    try:
        cur = conn.execute(
            """UPDATE worker_jobs SET status = 'cancelled', finished_at = datetime('now'), updated_at = datetime('now'),
                lease_node_id = NULL, lease_token = NULL, leased_at = NULL, lease_expires_at = NULL,
                error_code = NULL, error_message = NULL
             WHERE id = ? AND status = 'leased' AND cancel_requested_at IS NOT NULL AND finished_at IS NULL""",
            (job_id,),
        )
        conn.commit()
        return cur.rowcount == 1
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        return False


def log_event(
    conn: sqlite3.Connection,
    *,
    job_id: int,
    event_type: str,
    attempt_id: Optional[int] = None,
    level: str = "info",
    message: Optional[str] = None,
    details_json: Optional[Mapping[str, Any]] = None,
) -> None:
    if not tables_ready(conn) or job_id < 1:
        return
    et = (event_type or "").strip()
    if not et:
        return
    aid = int(attempt_id) if attempt_id is not None and int(attempt_id) >= 1 else None
    lv = (level or "").strip() or "info"
    msg = _safe_message(message) if message else None
    det = _json_dumps(dict(details_json) if details_json else None)
    try:
        conn.execute(
            """INSERT INTO worker_job_events (job_id, attempt_id, event_type, level, message, details_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
            (job_id, aid, et, lv, msg or None, det),
        )
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass


def row_to_job(row: Optional[Any]) -> Optional[dict[str, Any]]:
    """Convert sqlite3.Row or mapping to a plain dict (optional helper for callers)."""
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        return dict(row)
    if isinstance(row, Mapping):
        return dict(row)
    return None
