"""
Run full scanner phase parity for a collector job in an isolated local SQLite DB.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
import traceback
from pathlib import Path
from typing import Any

from sqlite_pragmas import apply_surveytrace_pragmas

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_SQL = REPO_ROOT / "sql" / "schema.sql"
SCANNER_DIR = REPO_ROOT / "daemon"


def _apply_schema(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path), timeout=30)
    try:
        apply_surveytrace_pragmas(conn)
        conn.executescript(SCHEMA_SQL.read_text(encoding="utf-8"))
        conn.commit()
    finally:
        conn.close()


def _seed_runtime_config(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path), timeout=30)
    try:
        apply_surveytrace_pragmas(conn)
        # Keep parity behavior, but avoid cloud callbacks from edge collectors by default.
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES ('ai_enrichment_enabled', '0')"
        )
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES ('ai_provider', 'ollama')"
        )
        conn.commit()
    finally:
        conn.close()


def _insert_job(db_path: Path, job: dict[str, Any]) -> int:
    phases = job.get("phases", [])
    if not isinstance(phases, list):
        phases = []
    # Collector runs local discovery/fingerprint phases only.
    # CVE/AI enrichment is intentionally deferred to master ingest.
    phases = [p for p in phases if str(p).strip().lower() != "cve"]
    if "banner" not in phases:
        phases.append("banner")
    if "fingerprint" not in phases:
        phases.append("fingerprint")

    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        apply_surveytrace_pragmas(conn)
        cur = conn.execute(
            """
            INSERT INTO scan_jobs
                (status, target_cidr, label, exclusions, phases, rate_pps, inter_delay,
                 scan_mode, profile, priority, collector_id, created_by)
            VALUES
                ('queued', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'collector')
            """,
            (
                str(job.get("target_cidr", "")),
                str(job.get("label", "")),
                str(job.get("exclusions", "")),
                json.dumps(phases, separators=(",", ":"), ensure_ascii=False),
                int(job.get("rate_pps", 5)),
                int(job.get("inter_delay", 200)),
                str(job.get("scan_mode", "auto")),
                str(job.get("profile", "standard_inventory")),
                int(job.get("priority", 10)),
                int(job.get("collector_id", 1)),
            ),
        )
        job_id = int(cur.lastrowid)
        conn.commit()
        return job_id
    finally:
        conn.close()


def _extract_payload(db_path: Path, job_id: int) -> dict[str, Any]:
    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        apply_surveytrace_pragmas(conn)
        job_row = conn.execute(
            "SELECT status, hosts_found, hosts_scanned, summary_json, error_msg FROM scan_jobs WHERE id=?",
            (job_id,),
        ).fetchone()
        assets = [dict(r) for r in conn.execute("SELECT * FROM assets WHERE last_scan_id=? ORDER BY ip ASC", (job_id,)).fetchall()]
        findings = [dict(r) for r in conn.execute(
            """
            SELECT f.*
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            WHERE a.last_scan_id = ?
            ORDER BY f.cvss DESC, f.id DESC
            """,
            (job_id,),
        ).fetchall()]
        logs = [dict(r) for r in conn.execute(
            "SELECT level, ip, message FROM scan_log WHERE job_id=? ORDER BY id ASC",
            (job_id,),
        ).fetchall()]
        ports = [dict(r) for r in conn.execute(
            "SELECT p.asset_id, p.ports, a.ip FROM port_history p JOIN assets a ON a.id=p.asset_id WHERE p.scan_id=?",
            (job_id,),
        ).fetchall()]
        return {
            "scan_job": {
                "status": str(job_row["status"] if job_row else "failed"),
                "hosts_found": int(job_row["hosts_found"] if job_row and job_row["hosts_found"] is not None else 0),
                "hosts_scanned": int(job_row["hosts_scanned"] if job_row and job_row["hosts_scanned"] is not None else 0),
                "summary_json": str(job_row["summary_json"] if job_row and job_row["summary_json"] else ""),
                "error_msg": str(job_row["error_msg"] if job_row and job_row["error_msg"] else ""),
            },
            "assets": assets,
            "findings": findings,
            "scan_log": logs,
            "port_history": ports,
        }
    finally:
        conn.close()


def run_collector_parity(job: dict[str, Any]) -> dict[str, Any]:
    tmp_root = Path(tempfile.mkdtemp(prefix="surveytrace-collector-"))
    db_path = tmp_root / "surveytrace.db"
    data_dir = tmp_root
    nvd_source = REPO_ROOT / "data" / "nvd.db"
    nvd_target = data_dir / "nvd.db"
    try:
        _apply_schema(db_path)
        _seed_runtime_config(db_path)
        if nvd_source.exists():
            try:
                os.symlink(str(nvd_source), str(nvd_target))
            except Exception:
                shutil.copy2(nvd_source, nvd_target)
        job_id = _insert_job(db_path, job)

        import sys
        if str(SCANNER_DIR) not in sys.path:
            sys.path.insert(0, str(SCANNER_DIR))
        import scanner_daemon  # type: ignore

        scanner_daemon.DB_PATH = db_path
        scanner_daemon.DATA_DIR = data_dir
        scanner_daemon.OUI_MAP_PATH = data_dir / "oui_map.json"
        scanner_daemon.WEBFP_RULES_PATH = data_dir / "webfp_rules.json"
        row = None
        with scanner_daemon.db_conn() as conn:
            row = conn.execute("SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise RuntimeError("collector parity job row missing")
        scanner_daemon.run_scan(dict(row))
        payload = _extract_payload(db_path, job_id)
        payload["scan_log"].append(
            {"level": "INFO", "ip": "", "message": "collector parity runner completed full local phase execution"}
        )
        return payload
    except Exception as exc:
        return {
            "scan_job": {"status": "failed", "error_msg": str(exc)[:400]},
            "assets": [],
            "findings": [],
            "scan_log": [{"level": "ERR", "ip": "", "message": f"collector parity runner failed: {exc}"}],
            "port_history": [],
            "traceback": traceback.format_exc()[:8000],
        }
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)
