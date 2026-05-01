"""
Phase 9 — change detection: in-app alerts and CVE finding lifecycle.

Alert types: new_asset, port_change, new_cve, finding_reopened, finding_mitigated.

Finding lifecycle: new → active (still present on a later scan); mitigated when absent
from correlated results; accepted (manual risk acceptance); reopened when a mitigated
finding matches again. Accepted findings are not auto-mitigated when absent.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any, Iterable

log = logging.getLogger(__name__)

# Match scanner_daemon._BULK_WRITE_COMMIT_INTERVAL: release the SQLite writer between
# batches so PHP / other daemons are not blocked for one huge CVE lifecycle transaction.
BULK_COMMIT_INTERVAL = 100

# Avoid enormous `WHERE asset_id IN (...)` clauses (parser/VM limits + long locks).
_MAX_ASSET_ID_IN_CHUNK = 300

ALERT_TYPES = frozenset(
    {
        "new_asset",
        "port_change",
        "new_cve",
        "finding_reopened",
        "finding_mitigated",
    }
)


def insert_change_alert(
    conn: sqlite3.Connection,
    alert_type: str,
    job_id: int,
    *,
    asset_id: int | None = None,
    finding_id: int | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    if alert_type not in ALERT_TYPES:
        log.warning("unknown change_alerts.alert_type=%s", alert_type)
    # Risk-accepted findings stay in the DB for audit but should not generate more CVE alerts.
    if finding_id is not None:
        row = conn.execute(
            "SELECT COALESCE(lifecycle_state, 'active') AS st FROM findings WHERE id = ?",
            (int(finding_id),),
        ).fetchone()
        if row and str(row["st"] or "").strip().lower() == "accepted":
            return
    dj = json.dumps(detail, separators=(",", ":"), ensure_ascii=False) if detail else None
    conn.execute(
        """INSERT INTO change_alerts (alert_type, job_id, asset_id, finding_id, detail_json)
           VALUES (?,?,?,?,?)""",
        (alert_type, job_id, asset_id, finding_id, dj),
    )


def open_ports_json_to_set(open_ports_json: str | None) -> frozenset[int]:
    try:
        arr = json.loads(open_ports_json or "[]")
        if not isinstance(arr, list):
            return frozenset()
        out: set[int] = set()
        for x in arr:
            try:
                pi = int(x)
                if 1 <= pi <= 65535:
                    out.add(pi)
            except (TypeError, ValueError):
                continue
        return frozenset(out)
    except (TypeError, ValueError, json.JSONDecodeError):
        return frozenset()


def maybe_alert_port_change(
    conn: sqlite3.Connection,
    job_id: int,
    ip: str,
    asset_id: int,
    prev_ports_json: str | None,
    new_ports: list[Any],
) -> None:
    old_s = open_ports_json_to_set(prev_ports_json)
    new_s: set[int] = set()
    for p in new_ports:
        try:
            pi = int(p)
            if 1 <= pi <= 65535:
                new_s.add(pi)
        except (TypeError, ValueError):
            continue
    nfs = frozenset(new_s)
    if old_s == nfs:
        return
    insert_change_alert(
        conn,
        "port_change",
        job_id,
        asset_id=asset_id,
        detail={
            "ip": ip,
            "added_ports": sorted(nfs - old_s),
            "removed_ports": sorted(old_s - nfs),
        },
    )


def _apply_one_finding_row(
    conn: sqlite3.Connection,
    job_id: int,
    f: dict[str, Any],
) -> None:
    aid = int(f["asset_id"])
    ip = str(f["ip"])
    cve = str(f["cve_id"]).strip()
    cvss = float(f.get("cvss") or 0.0)
    sev = str(f.get("severity") or "info")
    desc = str(f.get("description") or "")[:2000]
    pub = str(f.get("published") or "")[:64]

    row = conn.execute(
        "SELECT id, lifecycle_state, resolved FROM findings WHERE asset_id=? AND cve_id=?",
        (aid, cve),
    ).fetchone()

    if row is None:
        conn.execute(
            """INSERT INTO findings (asset_id, ip, cve_id, cvss, severity, description, published,
                lifecycle_state, first_seen_job_id, last_seen_job_id, resolved, confirmed_at)
                VALUES (?,?,?,?,?,?,?, 'new', ?, ?, 0, CURRENT_TIMESTAMP)""",
            (aid, ip, cve, cvss, sev, desc, pub, job_id, job_id),
        )
        fid = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        insert_change_alert(
            conn,
            "new_cve",
            job_id,
            asset_id=aid,
            finding_id=fid,
            detail={"ip": ip, "cve_id": cve},
        )
        return

    fid = int(row["id"])
    st = (str(row["lifecycle_state"] or "active")).strip().lower()
    if st not in ("new", "active", "mitigated", "accepted", "reopened"):
        st = "active"

    if st == "mitigated":
        conn.execute(
            """UPDATE findings SET cvss=?, severity=?, description=?, published=?,
                lifecycle_state='reopened', resolved=0, mitigated_at=NULL, last_seen_job_id=?
                WHERE id=?""",
            (cvss, sev, desc, pub, job_id, fid),
        )
        insert_change_alert(
            conn,
            "finding_reopened",
            job_id,
            asset_id=aid,
            finding_id=fid,
            detail={"ip": ip, "cve_id": cve, "from": "mitigated"},
        )
        return

    if st == "accepted":
        conn.execute(
            """UPDATE findings SET cvss=?, severity=?, description=?, published=?,
                last_seen_job_id=? WHERE id=?""",
            (cvss, sev, desc, pub, job_id, fid),
        )
        return

    if st == "new":
        conn.execute(
            """UPDATE findings SET cvss=?, severity=?, description=?, published=?,
                lifecycle_state='active', last_seen_job_id=?, resolved=0 WHERE id=?""",
            (cvss, sev, desc, pub, job_id, fid),
        )
        return

    conn.execute(
        """UPDATE findings SET cvss=?, severity=?, description=?, published=?,
            last_seen_job_id=?, resolved=0 WHERE id=?""",
        (cvss, sev, desc, pub, job_id, fid),
    )


def _mark_missing_findings_mitigated(
    conn: sqlite3.Connection,
    job_id: int,
    present: set[tuple[int, str]],
    asset_ids: set[int],
    *,
    commit_interval: int,
) -> int:
    """Returns number of mitigated rows (for metrics). Commits every commit_interval mitigations."""
    if not asset_ids:
        return 0
    mitigated_count = 0
    aid_list = sorted(int(x) for x in asset_ids)
    for cstart in range(0, len(aid_list), _MAX_ASSET_ID_IN_CHUNK):
        chunk = aid_list[cstart : cstart + _MAX_ASSET_ID_IN_CHUNK]
        ph = ",".join("?" * len(chunk))
        rows = conn.execute(
            f"""SELECT id, asset_id, cve_id FROM findings
                WHERE asset_id IN ({ph})
                  AND lifecycle_state IN ('new','active','reopened')""",
            tuple(chunk),
        ).fetchall()
        for r in rows:
            aid = int(r["asset_id"])
            cve = str(r["cve_id"])
            if (aid, cve) in present:
                continue
            fid = int(r["id"])
            conn.execute(
                """UPDATE findings SET lifecycle_state='mitigated', mitigated_at=CURRENT_TIMESTAMP,
                    resolved=1, last_seen_job_id=? WHERE id=?""",
                (job_id, fid),
            )
            insert_change_alert(
                conn,
                "finding_mitigated",
                job_id,
                asset_id=aid,
                finding_id=fid,
                detail={"cve_id": cve, "reason": "absent_from_scan"},
            )
            mitigated_count += 1
            if commit_interval > 0 and mitigated_count % commit_interval == 0:
                conn.commit()
    return mitigated_count


def _refresh_top_cve_for_asset_ids(
    conn: sqlite3.Connection,
    asset_ids: set[int],
    *,
    commit_interval: int,
) -> None:
    """
    Recompute assets.top_cve / top_cvss only for IPs touched by this scan.

    The previous global UPDATE (all assets that appear in findings) could lock SQLite
    for a long time on large databases at end-of-scan.
    """
    if not asset_ids:
        return
    aid_list = sorted(int(x) for x in asset_ids)
    chunk_size = 200
    chunks = 0
    for cstart in range(0, len(aid_list), chunk_size):
        chunk = aid_list[cstart : cstart + chunk_size]
        ph = ",".join("?" * len(chunk))
        conn.execute(
            f"""UPDATE assets SET
                top_cve = (
                    SELECT cve_id FROM findings
                    WHERE asset_id = assets.id AND resolved = 0
                    ORDER BY cvss DESC LIMIT 1
                ),
                top_cvss = (
                    SELECT cvss FROM findings
                    WHERE asset_id = assets.id AND resolved = 0
                    ORDER BY cvss DESC LIMIT 1
                )
                WHERE id IN ({ph})""",
            tuple(chunk),
        )
        chunks += 1
        if commit_interval > 0 and chunks % max(1, commit_interval // 50) == 0:
            conn.commit()


def apply_scan_findings_lifecycle(
    conn: sqlite3.Connection,
    job_id: int,
    findings: list[dict[str, Any]],
    upserted_asset_ids: Iterable[int],
    *,
    commit_interval: int = BULK_COMMIT_INTERVAL,
) -> None:
    """
    Apply per-finding upserts with lifecycle rules, mark absent CVEs mitigated for
    assets touched in this scan, then refresh assets.top_cve / top_cvss.

    Commits periodically (default every BULK_COMMIT_INTERVAL finding rows) so the
    writer lock is not held across tens of thousands of CVE upserts.
    """
    present: set[tuple[int, str]] = set()
    for f in findings:
        try:
            aid = int(f["asset_id"])
            cve = str(f["cve_id"]).strip()
        except (TypeError, ValueError, KeyError):
            continue
        if cve:
            present.add((aid, cve))

    for i, f in enumerate(findings):
        _apply_one_finding_row(conn, job_id, f)
        if commit_interval > 0 and (i + 1) % commit_interval == 0:
            conn.commit()

    asset_ids = {int(x) for x in upserted_asset_ids}
    _mark_missing_findings_mitigated(conn, job_id, present, asset_ids, commit_interval=commit_interval)

    _refresh_top_cve_for_asset_ids(conn, asset_ids, commit_interval=commit_interval)
    conn.commit()
