"""
SurveyTrace — credentialed check worker (SSH os_release + package_inventory + SNMPv3 device identity).

Leases worker_jobs with job_type credentialed_check, executes ssh.linux.os_release@1.0.0 over SSH when
the job selects that plugin (bounded SFTP/exec read of /etc/os-release only). Other plugins stay
skipped/not_implemented. Optional SURVEYTRACE_CRED_CHECK_PLACEHOLDER_ONLY=1 forces placeholder-mode skips
(smoke tests). Writes credential_check_results, small stdout artifacts, and os_version_observations.

SSH host keys for plugins: **SURVEYTRACE_CRED_SSH_CHECK_HOST_KEY_POLICY** (preferred; e.g. accept_new
for many assets) or legacy **SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY** — see ``cred_check_ssh_os_release.py``.

SSH connect failures log a WARNING from cred_check_ssh_os_release / cred_check_ssh_packages
(host, port, user, code, sanitized detail). Failed plugin rows may include error_detail_safe
(PHP/UI preview). On the worker host, run the probe with this unit's Python (**venv**, not system python3):
``/opt/surveytrace/venv/bin/python3 /opt/surveytrace/daemon/cred_ssh_probe_cli.py --profile-id=… --host=…``
with the same SURVEYTRACE_INSTALL_DIR / SURVEYTRACE_DB_PATH as this process. The probe auto-loads
/etc/surveytrace/surveytrace.env when present so PHP decrypt matches this unit's EnvironmentFile.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Mapping

from surveytrace_paths import main_db_path

DAEMON_DIR = Path(__file__).resolve().parent
if str(DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(DAEMON_DIR))

import worker_jobs as wj  # noqa: E402
from cred_check_run import process_cred_check_run  # noqa: E402
from sqlite_pragmas import apply_surveytrace_pragmas  # noqa: E402

log = logging.getLogger("credential_check_worker")

JOB_TYPE = "credentialed_check"
ENTITY_TYPE = "credential_check_run"


def _poll_secs() -> float:
    raw = (os.environ.get("SURVEYTRACE_CRED_CHECK_POLL_SECS") or "3").strip()
    try:
        v = float(raw)
    except ValueError:
        v = 3.0
    return max(1.0, min(60.0, v))


def _node_key() -> str:
    raw = (os.environ.get("SURVEYTRACE_CRED_CHECK_NODE_KEY") or "").strip()
    if raw:
        return raw[:200]
    hn = socket.gethostname() or "host"
    return f"cred_check:{hn}"[:200]


def _audit(conn: sqlite3.Connection, action: str, details: Mapping[str, Any]) -> None:
    try:
        conn.execute(
            """
            INSERT INTO user_audit_log
                (actor_user_id, actor_username, target_user_id, target_username, action, details_json, source_ip)
            VALUES
                (NULL, 'system', NULL, NULL, ?, ?, '127.0.0.1')
            """,
            (action, json.dumps(dict(details), separators=(",", ":"), ensure_ascii=False)),
        )
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass


def _job_cancel_requested(conn: sqlite3.Connection, job_id: int) -> bool:
    row = conn.execute(
        "SELECT cancel_requested_at FROM worker_jobs WHERE id = ? LIMIT 1",
        (job_id,),
    ).fetchone()
    if not row:
        return False
    v = row[0] if not isinstance(row, sqlite3.Row) else row["cancel_requested_at"]
    return v is not None and str(v).strip() != ""


def _sync_run_terminal_from_worker(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    status: str,
    summary: Mapping[str, Any],
    pending_targets: str | None,
) -> None:
    """Keep credential_check_runs / pending targets aligned with terminal worker_jobs outcomes."""
    if run_id < 1:
        return
    try:
        sj = json.dumps(dict(summary), separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        sj = "{}"
    try:
        conn.execute(
            """UPDATE credential_check_runs SET status = ?, finished_at = datetime('now'), summary_json = ?
             WHERE id = ? AND status IN ('queued','resolving_targets','ready','running')""",
            (status, sj, run_id),
        )
        if pending_targets == "cancelled":
            conn.execute(
                """UPDATE credential_check_run_targets SET status = 'skipped', error_code = 'user_cancelled',
                    error_message_safe = 'cancelled', finished_at = datetime('now')
                 WHERE run_id = ? AND status = 'pending'""",
                (run_id,),
            )
        elif pending_targets == "failed":
            conn.execute(
                """UPDATE credential_check_run_targets SET status = 'skipped', error_code = 'worker_failed',
                    error_message_safe = 'worker error', finished_at = datetime('now')
                 WHERE run_id = ? AND status = 'pending'""",
                (run_id,),
            )
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass


def _parse_run_id(job: Mapping[str, Any]) -> int:
    eid = job.get("entity_id")
    if eid is not None and int(eid) >= 1:
        return int(eid)
    raw = job.get("payload_json")
    if not raw:
        return 0
    try:
        doc = json.loads(str(raw))
    except (TypeError, ValueError):
        return 0
    if not isinstance(doc, dict):
        return 0
    rid = doc.get("credential_check_run_id")
    try:
        return int(rid) if rid is not None and int(rid) >= 1 else 0
    except (TypeError, ValueError):
        return 0


def _process_one(conn: sqlite3.Connection, *, node_id: int, job: Mapping[str, Any]) -> None:
    jid = int(job["id"])
    rid_early = _parse_run_id(job)
    if _job_cancel_requested(conn, jid):
        if rid_early >= 1:
            _sync_run_terminal_from_worker(
                conn,
                rid_early,
                status="cancelled",
                summary={"reason": "cancel_before_worker_start", "worker_job_id": jid},
                pending_targets="cancelled",
            )
        wj.finish_job_cancelled(conn, jid, result_summary_json={"reason": "cancel_before_start", "worker": "credential_check_worker"})
        return

    attempt_id = wj.start_attempt(conn, jid, node_id=node_id)
    if attempt_id < 1:
        if _job_cancel_requested(conn, jid):
            wj.finalize_leased_cancel(conn, jid)
            if rid_early >= 1:
                _sync_run_terminal_from_worker(
                    conn,
                    rid_early,
                    status="cancelled",
                    summary={"reason": "cancel_leased_no_attempt", "worker_job_id": jid},
                    pending_targets="cancelled",
                )
            wj.finish_job_cancelled(conn, jid, result_summary_json={"reason": "cancel_leased_no_attempt"})
        return

    run_id = _parse_run_id(job)
    if run_id < 1:
        wj.finish_attempt(
            conn,
            attempt_id,
            status="failed",
            error_code="validation_error",
            error_message="missing credential_check_run_id",
        )
        wj.fail_job(conn, jid, error_code="validation_error", error_message="missing run id on job")
        fb = 0
        try:
            if job.get("entity_id") is not None:
                fb = int(job["entity_id"])
        except (TypeError, ValueError):
            fb = 0
        if fb >= 1:
            _sync_run_terminal_from_worker(
                conn,
                fb,
                status="failed",
                summary={"reason": "missing_run_parse", "worker_job_id": jid},
                pending_targets="failed",
            )
        return

    row = conn.execute(
        "SELECT id, status, summary_json FROM credential_check_runs WHERE id = ? LIMIT 1",
        (run_id,),
    ).fetchone()
    if not row:
        wj.finish_attempt(conn, attempt_id, status="failed", error_code="dependency_missing", error_message="run row missing")
        wj.fail_job(conn, jid, error_code="dependency_missing", error_message="run row missing")
        return

    st = str(row["status"])
    if st == "cancelled":
        wj.log_event(
            conn,
            job_id=jid,
            attempt_id=attempt_id,
            event_type="cred_check_run_aborted",
            level="info",
            message="Run already cancelled before execution",
            details_json={"credential_check_run_id": run_id},
        )
        try:
            conn.execute(
                """UPDATE credential_check_run_targets SET status = 'skipped', error_code = 'user_cancelled',
                    error_message_safe = 'cancelled', finished_at = datetime('now') WHERE run_id = ? AND status = 'pending'""",
                (run_id,),
            )
            conn.commit()
        except sqlite3.Error:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
        wj.finish_attempt(conn, attempt_id, status="cancelled", error_message="run cancelled by operator")
        wj.finish_job_cancelled(conn, jid, result_summary_json={"credential_check_run_id": run_id, "reason": "run_already_cancelled"})
        return

    conn.execute(
        "UPDATE credential_check_runs SET status = 'running' WHERE id = ? AND status IN ('queued','ready','resolving_targets')",
        (run_id,),
    )
    conn.commit()
    wj.log_event(
        conn,
        job_id=jid,
        attempt_id=attempt_id,
        event_type="cred_check_run_executing",
        level="info",
        message="Run marked running; processing targets",
        details_json={"credential_check_run_id": run_id},
    )

    counts = process_cred_check_run(
        conn,
        run_id=run_id,
        jid=jid,
        cancel_requested=lambda: _job_cancel_requested(conn, jid),
        audit=_audit,
    )

    if counts.get("error") == "job_missing":
        wj.finish_attempt(conn, attempt_id, status="failed", error_code="dependency_missing", error_message="job row missing for run")
        wj.fail_job(conn, jid, error_code="dependency_missing", error_message="job row missing for run")
        return

    if _job_cancel_requested(conn, jid):
        pend_row = conn.execute(
            "SELECT COUNT(*) FROM credential_check_run_targets WHERE run_id = ? AND status = 'pending'",
            (run_id,),
        ).fetchone()
        pending_left = int(pend_row[0]) if pend_row else 0
        if pending_left > 0:
            conn.execute(
                "UPDATE credential_check_runs SET status = 'cancelled', finished_at = datetime('now') WHERE id = ?",
                (run_id,),
            )
            conn.execute(
                """UPDATE credential_check_run_targets SET status = 'skipped', error_code = 'user_cancelled',
                    error_message_safe = 'cancelled', finished_at = datetime('now')
                 WHERE run_id = ? AND status = 'pending'""",
                (run_id,),
            )
            conn.commit()
            wj.finish_attempt(conn, attempt_id, status="cancelled", error_message="operator cancel")
            wj.finish_job_cancelled(
                conn,
                jid,
                result_summary_json={
                    "credential_check_run_id": run_id,
                    "pending_targets_cancelled": pending_left,
                },
            )
            _audit(
                conn,
                "credential_check.run_completed",
                {
                    "run_id": run_id,
                    "worker_job_id": jid,
                    "outcome": "cancelled_mid_worker",
                    "pending_targets_cancelled": pending_left,
                },
            )
            return

    summary = dict(counts)
    run_outcome = str(summary.get("run_outcome") or "success")
    run_status = "failed" if run_outcome == "failed" else "completed"
    attempt_status = "failed" if run_outcome == "failed" else "completed"
    sum_s = json.dumps(summary, separators=(",", ":"), ensure_ascii=False)
    conn.execute(
        "UPDATE credential_check_runs SET status = ?, finished_at = datetime('now'), summary_json = ? WHERE id = ?",
        (run_status, sum_s, run_id),
    )
    conn.commit()
    wj.log_event(
        conn,
        job_id=jid,
        attempt_id=attempt_id,
        event_type="cred_check_run_finishing",
        level="info",
        message="Run targets finished; finalizing worker attempt",
        details_json={
            "credential_check_run_id": run_id,
            "targets_completed": int(summary.get("targets_completed") or 0),
            "targets_failed": int(summary.get("targets_failed") or 0),
            "targets_skipped": int(summary.get("targets_skipped") or 0),
            "run_outcome": run_outcome,
            "result_success_count": int(summary.get("result_success_count") or 0),
            "result_failed_count": int(summary.get("result_failed_count") or 0),
            "result_partial_count": int(summary.get("result_partial_count") or 0),
        },
    )

    wj.finish_attempt(
        conn,
        attempt_id,
        status=attempt_status,
        metrics_json={
            "credential_check_run_id": run_id,
            "targets_skipped": int(summary.get("targets_skipped") or 0),
            "targets_completed": int(summary.get("targets_completed") or 0),
            "targets_failed": int(summary.get("targets_failed") or 0),
            "run_outcome": run_outcome,
            "result_success_count": int(summary.get("result_success_count") or 0),
            "result_failed_count": int(summary.get("result_failed_count") or 0),
            "result_partial_count": int(summary.get("result_partial_count") or 0),
        },
    )
    job_summary = {
        "credential_check_run_id": run_id,
        "status": run_status,
        "run_outcome": run_outcome,
        "slice": 9,
    }
    if run_outcome == "failed":
        # Mirror run failure on worker_jobs (finish_job always marks completed).
        wj.fail_job(
            conn,
            jid,
            error_code="transport_error",
            error_message="All targets failed plugin checks (no successful plugin rows).",
            result_summary_json=summary,
        )
    else:
        wj.finish_job(conn, jid, result_summary_json={**summary, **job_summary})
    _audit(
        conn,
        "credential_check.run_completed",
        {
            "run_id": run_id,
            "worker_job_id": jid,
            "targets_skipped": int(summary.get("targets_skipped") or 0),
            "targets_completed": int(summary.get("targets_completed") or 0),
            "targets_failed": int(summary.get("targets_failed") or 0),
            "run_outcome": run_outcome,
            "result_success_count": int(summary.get("result_success_count") or 0),
            "result_failed_count": int(summary.get("result_failed_count") or 0),
            "result_partial_count": int(summary.get("result_partial_count") or 0),
        },
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [cred_check] %(message)s")
    p = argparse.ArgumentParser(
        description="SurveyTrace credentialed check worker (SSH + SNMPv3 cred-check plugins)"
    )
    p.add_argument("--once", action="store_true", help="Process at most one job then exit")
    args = p.parse_args()

    db_path = main_db_path()
    if not db_path.is_file():
        log.error("database not found: %s", db_path)
        sys.exit(1)

    poll = _poll_secs()
    node_key = _node_key()
    log.info("starting node_key=%s db=%s poll=%ss", node_key, db_path, poll)

    conn = sqlite3.connect(str(db_path), timeout=60.0)
    conn.row_factory = sqlite3.Row
    apply_surveytrace_pragmas(conn)

    if not wj.tables_ready(conn):
        log.error("worker_jobs substrate not migrated")
        sys.exit(1)

    node_id = wj.register_node(conn, node_key=node_key, hostname=socket.gethostname(), role="credential_check", status="healthy")
    if node_id < 1:
        log.error("register_node failed")
        sys.exit(1)

    while True:
        try:
            wj.heartbeat(conn, node_id=node_id, worker_type="credential_check", status="healthy")
            job = wj.lease_next_job(conn, lease_node_id=node_id, lease_ttl_sec=300, allowed_job_types=[JOB_TYPE])
            if not job:
                if args.once:
                    break
                time.sleep(poll)
                continue
            jid = int(job["id"])
            if _job_cancel_requested(conn, jid):
                wj.finish_job_cancelled(conn, jid, result_summary_json={"reason": "cancel_before_attempt"})
                if args.once:
                    break
                continue
            try:
                _process_one(conn, node_id=node_id, job=job)
            except Exception as e:
                log.exception("process_one failed job_id=%s", jid)
                try:
                    rid_err = _parse_run_id(job)
                    if rid_err >= 1:
                        _sync_run_terminal_from_worker(
                            conn,
                            rid_err,
                            status="failed",
                            summary={"reason": "worker_exception", "worker_job_id": jid},
                            pending_targets="failed",
                        )
                except Exception:
                    pass
                try:
                    wj.fail_job(conn, jid, error_code="internal_error", error_message="credential_check_worker internal error")
                except Exception:
                    pass
            if args.once:
                break
        except KeyboardInterrupt:
            log.info("interrupt, exiting")
            break
        except Exception as e:
            log.exception("loop error: %s", e)
            time.sleep(poll)

    conn.close()


if __name__ == "__main__":
    main()
