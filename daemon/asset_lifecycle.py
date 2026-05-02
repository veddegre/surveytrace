"""
Phase 12 — asset lifecycle vs expected scan coverage (CIDR + per-job snapshots).

Expected set: assets whose IPv4/IPv6 address falls inside the job's target_cidr (comma-separated).
Observed set: asset_id values present in scan_asset_snapshots for that job after the run completes.
"""

from __future__ import annotations

import ipaddress
import logging
import sqlite3

import change_detection

log = logging.getLogger(__name__)


def ip_in_any_cidr(ip: str, cidr_csv: str | None) -> bool:
    s = (ip or "").strip()
    raw = (cidr_csv or "").strip()
    if not s or not raw:
        return False
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return False
    for part in raw.split(","):
        p = part.strip()
        if not p:
            continue
        try:
            net = ipaddress.ip_network(p, strict=False)
            if addr.version != net.version:
                continue
            if addr in net:
                return True
        except ValueError:
            continue
    return False


def evaluate_job_coverage_gaps(
    conn: sqlite3.Connection,
    job_id: int,
    target_cidr: str,
    observed_asset_ids: set[int],
) -> None:
    """Increment miss counters for in-scope assets missing from this job's snapshots; emit stale/retired alerts."""
    raw = (target_cidr or "").strip()
    if not raw:
        return
    try:
        rows = conn.execute(
            "SELECT id, ip, COALESCE(lifecycle_status,'active') AS ls, "
            "COALESCE(missed_scan_count,0) AS mc FROM assets"
        ).fetchall()
    except sqlite3.OperationalError as e:
        if "lifecycle_status" in str(e) or "missed_scan_count" in str(e):
            log.warning("[job %d] asset lifecycle columns missing; skip coverage evaluation: %s", job_id, e)
            return
        raise
    for r in rows:
        ip_s = str(r["ip"] or "").strip()
        if not ip_s or not ip_in_any_cidr(ip_s, raw):
            continue
        aid = int(r["id"])
        if aid in observed_asset_ids:
            continue
        old_ls = str(r["ls"] or "active").strip().lower()
        old_mc = int(r["mc"] or 0)
        new_mc = old_mc + 1
        new_ls = "retired" if new_mc >= 2 else "stale"
        try:
            conn.execute(
                """UPDATE assets SET
                    missed_scan_count = ?,
                    last_expected_scan_id = ?,
                    last_expected_scan_at = datetime('now'),
                    last_missed_scan_id = ?,
                    last_missed_scan_at = datetime('now'),
                    lifecycle_status = ?,
                    lifecycle_reason = 'missing_from_expected_scan',
                    retired_at = CASE
                        WHEN ? = 'retired' AND retired_at IS NULL THEN datetime('now')
                        ELSE retired_at
                    END
                WHERE id = ?""",
                (new_mc, job_id, job_id, new_ls, new_ls, aid),
            )
        except sqlite3.OperationalError as e:
            log.warning("[job %d] lifecycle UPDATE failed for asset %s: %s", job_id, aid, e)
            continue
        if old_ls not in ("stale", "retired") and new_ls == "stale":
            change_detection.insert_change_alert(
                conn,
                "asset_stale",
                job_id,
                asset_id=aid,
                detail={"ip": ip_s, "missed_scan_count": new_mc},
            )
        if old_ls != "retired" and new_ls == "retired":
            change_detection.insert_change_alert(
                conn,
                "asset_retired",
                job_id,
                asset_id=aid,
                detail={"ip": ip_s, "missed_scan_count": new_mc},
            )
