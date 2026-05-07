"""
Best-effort mirror: collector ingest → worker_jobs / worker_job_events (slice 4).

Observability only — failures here must never affect collector_ingest_queue or ingest outcomes.

Event volume: bounded by chunk/process_one cycles (one ingest_started per chunk attempt, plus
terminal/retry/partial/success hooks). No per-poll logging. Long-term retention / pruning of
worker_job_events for high-churn collectors is deferred (ops or future cron).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Mapping, Optional

import sqlite3

from worker_jobs import tables_ready

log = logging.getLogger("collector_ingest")

_MIRROR_TAG = "collector_ingest_v1"
_JOB_TYPE = "collector_ingest"
_ENTITY_TYPE = "collector_submission"


def _json_dumps(obj: Mapping[str, Any]) -> Optional[str]:
    try:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return None


def _submission_pk(conn: sqlite3.Connection, collector_id: int, job_id: int, submission_id: str) -> Optional[int]:
    row = conn.execute(
        "SELECT id FROM collector_submissions WHERE collector_id=? AND job_id=? AND submission_id=? LIMIT 1",
        (collector_id, job_id, submission_id),
    ).fetchone()
    if not row:
        return None
    return int(row["id"])


def _queue_counts(conn: sqlite3.Connection, collector_id: int, job_id: int, submission_id: str) -> tuple[int, int, int]:
    row = conn.execute(
        """SELECT
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS p,
            SUM(CASE WHEN status = 'applied' THEN 1 ELSE 0 END) AS a,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS f
           FROM collector_ingest_queue
           WHERE collector_id=? AND job_id=? AND submission_id=?""",
        (collector_id, job_id, submission_id),
    ).fetchone()
    if not row:
        return 0, 0, 0
    return (
        int(row["p"] or 0),
        int(row["a"] or 0),
        int(row["f"] or 0),
    )


def build_payload(
    conn: sqlite3.Connection,
    collector_id: int,
    job_id: int,
    submission_id: str,
    *,
    queue_row_id: Optional[int] = None,
    chunk_index: Optional[int] = None,
    chunk_count: Optional[int] = None,
) -> Optional[dict[str, Any]]:
    row = conn.execute(
        """SELECT id, chunk_count, received_chunks, processed_chunks, status
           FROM collector_submissions WHERE collector_id=? AND job_id=? AND submission_id=? LIMIT 1""",
        (collector_id, job_id, submission_id),
    ).fetchone()
    if not row:
        return None
    p, a, f = _queue_counts(conn, collector_id, job_id, submission_id)
    doc: dict[str, Any] = {
        "mirror": _MIRROR_TAG,
        "collector_id": int(collector_id),
        "scan_job_id": int(job_id),
        "submission_id": str(submission_id),
        "collector_submission_pk": int(row["id"]),
        "chunk_count": int(row["chunk_count"] or 0),
        "received_chunks": int(row["received_chunks"] or 0),
        "processed_chunks": int(row["processed_chunks"] or 0),
        "submission_status": str(row["status"] or ""),
        "ingest_queue_pending": p,
        "ingest_queue_applied": a,
        "ingest_queue_failed": f,
    }
    if queue_row_id is not None:
        doc["ingest_queue_row_id"] = int(queue_row_id)
    if chunk_index is not None:
        doc["chunk_index"] = int(chunk_index)
    if chunk_count is not None:
        doc["chunk_count_runtime"] = int(chunk_count)
    return doc


def _ensure_worker_job(conn: sqlite3.Connection, submission_pk: int, payload: dict[str, Any]) -> int:
    pj = _json_dumps(payload)
    if not pj:
        return 0
    row = conn.execute(
        f"""SELECT id FROM worker_jobs
            WHERE job_type=? AND entity_type=? AND entity_id=? LIMIT 1""",
        (_JOB_TYPE, _ENTITY_TYPE, submission_pk),
    ).fetchone()
    if row:
        wjid = int(row["id"])
        conn.execute(
            "UPDATE worker_jobs SET payload_json=?, updated_at=datetime('now') WHERE id=?",
            (pj, wjid),
        )
        return wjid
    try:
        conn.execute(
            """INSERT INTO worker_jobs (job_type, entity_type, entity_id, status, priority, max_attempts, payload_json, created_at, updated_at)
               VALUES (?, ?, ?, 'queued', 0, 8, ?, datetime('now'), datetime('now'))""",
            (_JOB_TYPE, _ENTITY_TYPE, submission_pk, pj),
        )
        row = conn.execute(
            "SELECT id FROM worker_jobs WHERE job_type=? AND entity_type=? AND entity_id=? LIMIT 1",
            (_JOB_TYPE, _ENTITY_TYPE, submission_pk),
        ).fetchone()
        return int(row["id"]) if row else 0
    except sqlite3.IntegrityError:
        row = conn.execute(
            "SELECT id FROM worker_jobs WHERE job_type=? AND entity_type=? AND entity_id=? LIMIT 1",
            (_JOB_TYPE, _ENTITY_TYPE, submission_pk),
        ).fetchone()
        return int(row["id"]) if row else 0
    except sqlite3.OperationalError:
        # Locked / busy — mirror drops; ingest continues in caller transaction.
        return 0


def _log_event(
    conn: sqlite3.Connection,
    job_id: int,
    event_type: str,
    message: str,
    details: Optional[Mapping[str, Any]] = None,
    attempt_id: Optional[int] = None,
) -> None:
    dj = _json_dumps(dict(details)) if details else None
    conn.execute(
        """INSERT INTO worker_job_events (job_id, attempt_id, event_type, level, message, details_json, created_at)
           VALUES (?, ?, ?, 'info', ?, ?, datetime('now'))""",
        (job_id, attempt_id, event_type, message[:2000], dj),
    )


def _start_attempt(conn: sqlite3.Connection, worker_job_id: int) -> int:
    conn.execute(
        """INSERT INTO worker_job_attempts (job_id, attempt_no, node_id, status, started_at)
           SELECT ?, COALESCE(MAX(attempt_no), 0) + 1, NULL, 'running', datetime('now')
           FROM worker_job_attempts WHERE job_id = ?""",
        (worker_job_id, worker_job_id),
    )
    row = conn.execute("SELECT last_insert_rowid() AS x").fetchone()
    aid = int(row["x"]) if row and row["x"] is not None else 0
    if aid > 0:
        conn.execute(
            """UPDATE worker_jobs SET status='running', attempts=(SELECT MAX(attempt_no) FROM worker_job_attempts WHERE job_id=?),
                updated_at=datetime('now'), lease_node_id=NULL, lease_token=NULL, leased_at=NULL, lease_expires_at=NULL
                WHERE id=?""",
            (worker_job_id, worker_job_id),
        )
    else:
        # Rare (e.g. last_insert_rowid edge); still mark mirror job active so health does not show stuck "queued" during ingest.
        conn.execute(
            """UPDATE worker_jobs SET status='running', updated_at=datetime('now'),
                lease_node_id=NULL, lease_token=NULL, leased_at=NULL, lease_expires_at=NULL WHERE id=?""",
            (worker_job_id,),
        )
    return aid


def _finish_attempt(conn: sqlite3.Connection, attempt_id: int, status: str, err_msg: Optional[str] = None) -> None:
    conn.execute(
        """UPDATE worker_job_attempts SET status=?, finished_at=datetime('now'), error_message=?
           WHERE id=?""",
        (status, (err_msg or "")[:2000] if err_msg else None, attempt_id),
    )


def ingest_chunk_begin(conn: sqlite3.Connection, qrow: dict, out: dict[str, Any]) -> None:
    """Mark mirror job running and open a new attempt for this chunk cycle."""
    out["wj_id"] = None
    out["attempt_id"] = None
    if not tables_ready(conn):
        return
    try:
        cid = int(qrow["collector_id"])
        jid = int(qrow["job_id"])
        sid = str(qrow.get("submission_id") or "")
        if not sid:
            return
        spk = _submission_pk(conn, cid, jid, sid)
        if spk is None:
            return
        pl = build_payload(
            conn,
            cid,
            jid,
            sid,
            queue_row_id=int(qrow.get("id") or 0) or None,
            chunk_index=int(qrow.get("chunk_index") or 0),
            chunk_count=int(qrow.get("chunk_count") or 0),
        )
        if not pl:
            return
        wjid = _ensure_worker_job(conn, spk, pl)
        if wjid < 1:
            return
        out["wj_id"] = wjid
        out["attempt_id"] = None
        chunk_meta = {
            "chunk_index": int(qrow.get("chunk_index") or 0),
            "chunk_count": int(qrow.get("chunk_count") or 0),
            "ingest_queue_row_id": int(qrow.get("id") or 0),
        }
        try:
            aid = _start_attempt(conn, wjid)
        except sqlite3.OperationalError:
            try:
                _log_event(
                    conn,
                    wjid,
                    "collector_mirror_attempt_begin_skipped",
                    "Mirror attempt not created (database busy); ingest continues.",
                    chunk_meta,
                    attempt_id=None,
                )
            except Exception:
                pass
        else:
            out["attempt_id"] = aid if aid > 0 else None
            if aid > 0:
                try:
                    _log_event(
                        conn,
                        wjid,
                        "collector_mirror_ingest_started",
                        "Master ingest started for one chunk.",
                        chunk_meta,
                        attempt_id=aid,
                    )
                except Exception:
                    pass
    except Exception:
        out["wj_id"] = None
        out["attempt_id"] = None


def on_chunk_applied_partial(
    conn: sqlite3.Connection,
    wjid: Optional[int],
    aid: Optional[int],
    qrow: dict,
    processed_chunks: int,
    chunk_count: int,
) -> None:
    if not wjid or not tables_ready(conn):
        return
    try:
        cid = int(qrow["collector_id"])
        jid = int(qrow["job_id"])
        sid = str(qrow.get("submission_id") or "")
        spk = _submission_pk(conn, cid, jid, sid)
        if spk is None:
            return
        pl = build_payload(conn, cid, jid, sid, queue_row_id=int(qrow.get("id") or 0) or None)
        if pl:
            pj = _json_dumps(pl)
            if pj:
                conn.execute(
                    "UPDATE worker_jobs SET payload_json=?, updated_at=datetime('now') WHERE id=?",
                    (pj, wjid),
                )
        _log_event(
            conn,
            wjid,
            "collector_mirror_chunk_applied",
            f"Chunk applied ({processed_chunks}/{chunk_count}); waiting for remaining chunks.",
            {"processed_chunks": processed_chunks, "chunk_count": chunk_count},
            attempt_id=aid,
        )
        if aid:
            _finish_attempt(conn, int(aid), "completed")
        conn.execute(
            """UPDATE worker_jobs SET status='running', updated_at=datetime('now') WHERE id=?""",
            (wjid,),
        )
    except Exception:
        pass


def on_scan_job_transitioned(
    conn: sqlite3.Connection,
    wjid: Optional[int],
    aid: Optional[int],
    scan_job_status: str,
) -> None:
    if not wjid or not tables_ready(conn):
        return
    try:
        _log_event(
            conn,
            wjid,
            "collector_mirror_scan_job_transitioned",
            f"Scan job set to {scan_job_status} after collector payload applied.",
            {"scan_job_status": scan_job_status},
            attempt_id=aid,
        )
    except Exception:
        pass


def on_pipeline_success(
    conn: sqlite3.Connection,
    wjid: Optional[int],
    aid: Optional[int],
    qrow: dict,
    scan_job_status: str,
    cve_count: int,
    ai_attempts: int,
    ai_applied: int,
) -> None:
    if not wjid or not tables_ready(conn):
        return
    try:
        cid = int(qrow["collector_id"])
        jid = int(qrow["job_id"])
        sid = str(qrow.get("submission_id") or "")
        spk = _submission_pk(conn, cid, jid, sid)
        if spk is None:
            return
        pl = build_payload(conn, cid, jid, sid)
        if pl:
            pl["master_enrichment"] = {
                "cve_matches": int(cve_count),
                "ai_attempts": int(ai_attempts),
                "ai_applied": int(ai_applied),
            }
            pj = _json_dumps(pl)
            if pj:
                conn.execute(
                    "UPDATE worker_jobs SET payload_json=?, updated_at=datetime('now') WHERE id=?",
                    (pj, wjid),
                )
        _log_event(
            conn,
            wjid,
            "collector_mirror_ingest_complete",
            "Collector ingest and master enrichment finished for this submission.",
            {"scan_job_status": scan_job_status},
            attempt_id=aid,
        )
        if aid:
            _finish_attempt(conn, int(aid), "completed")
        rs = _json_dumps(
            {
                "scan_job_status": scan_job_status,
                "cve_matches": int(cve_count),
                "ai_attempts": int(ai_attempts),
                "ai_applied": int(ai_applied),
            }
        )
        if not rs:
            rs = "{}"
        conn.execute(
            """UPDATE worker_jobs SET status='completed', finished_at=datetime('now'), updated_at=datetime('now'),
                lease_node_id=NULL, lease_token=NULL, leased_at=NULL, lease_expires_at=NULL,
                error_code=NULL, error_message=NULL,
                result_summary_json=? WHERE id=?""",
            (rs, wjid),
        )
    except Exception:
        pass


def on_retry_scheduled(
    conn: sqlite3.Connection,
    wjid: Optional[int],
    aid: Optional[int],
    qrow: dict,
    attempts_after: int,
    delay_sec: int,
    err_short: str,
) -> None:
    if not wjid or not tables_ready(conn):
        return
    try:
        cid = int(qrow["collector_id"])
        jid = int(qrow["job_id"])
        sid = str(qrow.get("submission_id") or "")
        spk = _submission_pk(conn, cid, jid, sid)
        pl = build_payload(conn, cid, jid, sid) if spk else None
        if pl:
            pl["last_ingest_error"] = err_short[:500]
            pj = _json_dumps(pl)
            if pj:
                conn.execute(
                    "UPDATE worker_jobs SET payload_json=?, status='retrying', updated_at=datetime('now') WHERE id=?",
                    (pj, wjid),
                )
        _log_event(
            conn,
            wjid,
            "collector_mirror_retry_scheduled",
            f"Ingest will retry after backoff ({delay_sec}s).",
            {"attempts": attempts_after, "delay_sec": delay_sec},
            attempt_id=aid,
        )
        if aid:
            _finish_attempt(conn, int(aid), "failed", err_short[:600])
    except Exception:
        pass


def on_terminal_failure(
    conn: sqlite3.Connection,
    wjid: Optional[int],
    aid: Optional[int],
    err_short: str,
) -> None:
    if not wjid or not tables_ready(conn):
        return
    try:
        conn.execute(
            """UPDATE worker_jobs SET status='failed', finished_at=datetime('now'), updated_at=datetime('now'),
                error_code='internal_error', error_message=?,
                lease_node_id=NULL, lease_token=NULL, leased_at=NULL, lease_expires_at=NULL WHERE id=?""",
            (err_short[:2000], wjid),
        )
        _log_event(
            conn,
            wjid,
            "collector_mirror_terminal_failure",
            "Collector ingest failed after max retries.",
            {},
            attempt_id=aid,
        )
        if aid:
            _finish_attempt(conn, int(aid), "failed", err_short[:600])
    except Exception:
        pass


def on_pre_stage_failure(
    conn: sqlite3.Connection,
    qrow: dict,
    err_short: str,
    attempts_after: int,
    terminal: bool,
) -> None:
    """Artifact missing / payload error before Stage A mirror begin."""
    if not tables_ready(conn):
        return
    try:
        cid = int(qrow["collector_id"])
        jid = int(qrow["job_id"])
        sid = str(qrow.get("submission_id") or "")
        spk = _submission_pk(conn, cid, jid, sid)
        if spk is None:
            return
        pl = build_payload(conn, cid, jid, sid)
        if not pl:
            return
        wjid = _ensure_worker_job(conn, spk, pl)
        if wjid < 1:
            return
        if terminal:
            on_terminal_failure(conn, wjid, None, err_short)
        else:
            on_retry_scheduled(conn, wjid, None, qrow, attempts_after, 0, err_short)
    except Exception:
        pass
