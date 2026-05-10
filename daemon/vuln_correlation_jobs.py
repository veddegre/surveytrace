"""
Enqueue offline vulnerability correlation jobs after inventory updates (best-effort; bounded).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any


def try_enqueue_vulnerability_correlation(conn: sqlite3.Connection, asset_id: int, run_id: int) -> None:
    """Insert at most one queued worker_jobs row per asset; no-op if tables missing or duplicate pending."""
    if asset_id < 1:
        return
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='worker_jobs' LIMIT 1"
        ).fetchone()
        if not row:
            return
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vulnerability_advisories' LIMIT 1"
        ).fetchone()
        if not row:
            return
        dup = conn.execute(
            """SELECT id FROM worker_jobs WHERE job_type = ? AND entity_type = ? AND entity_id = ?
               AND status IN ('queued', 'leased', 'running') LIMIT 1""",
            ("vulnerability_correlation", "asset", int(asset_id)),
        ).fetchone()
        if dup:
            return
        payload: dict[str, Any] = {"reason": "post_inventory", "run_id": int(run_id)}
        conn.execute(
            """INSERT INTO worker_jobs (job_type, entity_type, entity_id, status, priority, max_attempts, payload_json, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,datetime('now'),datetime('now'))""",
            (
                "vulnerability_correlation",
                "asset",
                int(asset_id),
                "queued",
                -5,
                2,
                json.dumps(payload, separators=(",", ":"), ensure_ascii=False)[:4000],
            ),
        )
    except sqlite3.Error:
        return
