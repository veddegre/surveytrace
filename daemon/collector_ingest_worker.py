"""
SurveyTrace collector ingest worker.

Reads collector_ingest_queue rows, applies chunk payloads into scan tables/assets/findings.
Then applies CVE and AI enrichment centrally on the master server.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import sys
import time
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "surveytrace.db"
INGEST_DIR = Path(__file__).parent.parent / "data" / "collector_ingest"
POLL_SECS = 3

logging.basicConfig(level=logging.INFO, format="%(asctime)s [collector_ingest] %(message)s")
log = logging.getLogger("collector_ingest")

DAEMON_DIR = Path(__file__).resolve().parent
if str(DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(DAEMON_DIR))
import change_detection  # type: ignore
import finding_triage  # type: ignore
import scanner_daemon  # type: ignore
from sqlite_pragmas import apply_surveytrace_pragmas

_INGEST_ROW_COMMIT_INTERVAL = 100

# Ensure shared scanner helpers point to this master's DB/NVD paths.
scanner_daemon.DB_PATH = DB_PATH
scanner_daemon.DATA_DIR = DB_PATH.parent
scanner_daemon.NVD_DB_PATH = DB_PATH.parent / "nvd.db"


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=60)
    conn.row_factory = sqlite3.Row
    apply_surveytrace_pragmas(conn)
    return conn


def _severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "none"


def _coerce_json_list(val: object) -> list:
    """Collector payloads often carry SQLite TEXT JSON as str; master expects native list before json.dumps."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        s = val.strip()
        if not s or s == "null":
            return []
        try:
            out = json.loads(s)
            return out if isinstance(out, list) else []
        except Exception:
            return []
    return []


def _master_refresh_scan_executive_summary(summary_doc: dict, job_id: int) -> dict:
    """
    Run-wide AI summary on the master using master's config.

    Collector chunks embed scan_job.summary_json from the collector host's daemon, which
    reads that machine's SQLite (often missing ai_enrichment_enabled=1) and records
    ai_scan_summary_status=skipped_disabled even when AI is enabled on the master.
    """
    if not isinstance(summary_doc, dict):
        return summary_doc
    try:
        ai_cfg = scanner_daemon._load_ai_enrichment_settings()
    except Exception:
        return summary_doc
    if not bool(ai_cfg.get("enabled")):
        return summary_doc
    try:
        ac = int(summary_doc.get("assets_catalogued") or 0)
    except (TypeError, ValueError):
        ac = 0
    if ac <= 0:
        return summary_doc
    if not bool(ai_cfg.get("available")):
        summary_doc["ai_scan_summary_status"] = "skipped_runtime"
        summary_doc["ai_scan_summary_detail"] = str(ai_cfg.get("availability_reason") or "runtime_unreachable")
        return summary_doc

    st = str(summary_doc.get("ai_scan_summary_status") or "")
    ai_sum = summary_doc.get("ai_summary")
    has_text = isinstance(ai_sum, dict) and (
        str(ai_sum.get("overview") or "").strip()
        or (
            isinstance(ai_sum.get("concerns"), list)
            and any(str(x).strip() for x in ai_sum["concerns"])
        )
        or (
            isinstance(ai_sum.get("next_steps"), list)
            and any(str(x).strip() for x in ai_sum["next_steps"])
        )
    )
    if st == "ok" and has_text:
        return summary_doc

    doc, err = scanner_daemon._run_ai_scan_summary_ollama(ai_cfg, summary_doc)
    if doc:
        summary_doc["ai_summary"] = doc
        summary_doc["ai_scan_summary_status"] = "ok"
        summary_doc["ai_scan_summary_detail"] = ""
        log.info("[job %d] executive AI summary refreshed on master (was status=%r)", job_id, st or None)
    else:
        summary_doc["ai_scan_summary_status"] = "failed"
        summary_doc["ai_scan_summary_detail"] = (err or "unknown")[:200]
        log.info("[job %d] executive AI summary on master failed: %s", job_id, (err or "")[:120])
    return summary_doc


def _coerce_json_dict(val: object) -> dict:
    if val is None:
        return {}
    if isinstance(val, dict):
        return val
    if isinstance(val, str):
        s = val.strip()
        if not s or s == "null":
            return {}
        try:
            out = json.loads(s)
            return out if isinstance(out, dict) else {}
        except Exception:
            return {}
    return {}


def _asset_upsert(conn: sqlite3.Connection, job_id: int, row: dict) -> tuple[int, dict]:
    """Returns (asset_id, meta) where meta has is_new (bool) and prev_open_ports (str|None)."""
    ip = str(row.get("ip", "")).strip()
    if ip == "":
        return 0, {"is_new": False, "prev_open_ports": None}
    existing = conn.execute("SELECT id, open_ports FROM assets WHERE ip=? LIMIT 1", (ip,)).fetchone()
    fields = {
        "hostname": row.get("hostname", ""),
        "mac": row.get("mac", ""),
        "mac_vendor": row.get("mac_vendor", ""),
        "category": row.get("category", "unk"),
        "vendor": row.get("vendor", ""),
        "model": row.get("model", ""),
        "os_guess": row.get("os_guess", ""),
        "cpe": row.get("cpe", ""),
        "connected_via": row.get("connected_via", ""),
        "open_ports": json.dumps(_coerce_json_list(row.get("open_ports")), separators=(",", ":"), ensure_ascii=False),
        "banners": json.dumps(_coerce_json_dict(row.get("banners")), separators=(",", ":"), ensure_ascii=False),
        "nmap_cpes": json.dumps(_coerce_json_list(row.get("nmap_cpes")), separators=(",", ":"), ensure_ascii=False),
        "discovery_sources": json.dumps(_coerce_json_list(row.get("discovery_sources")), separators=(",", ":"), ensure_ascii=False),
        "top_cve": row.get("top_cve", ""),
        "top_cvss": float(row.get("top_cvss", 0.0) or 0.0),
    }
    if existing:
        aid = int(existing["id"])
        prev_ports = str(existing["open_ports"] or "")
        conn.execute(
            """UPDATE assets SET
               hostname=:hostname, mac=:mac, mac_vendor=:mac_vendor, category=:category,
               vendor=:vendor, model=:model, os_guess=:os_guess, cpe=:cpe, connected_via=:connected_via,
               open_ports=:open_ports, banners=:banners, nmap_cpes=:nmap_cpes, discovery_sources=:discovery_sources,
               top_cve=:top_cve, top_cvss=:top_cvss, last_seen=datetime('now'), last_scan_id=:job_id
               WHERE id=:id""",
            {**fields, "id": aid, "job_id": job_id},
        )
        return aid, {"is_new": False, "prev_open_ports": prev_ports}
    conn.execute(
        """INSERT INTO assets
           (ip, hostname, mac, mac_vendor, category, vendor, model, os_guess, cpe, connected_via,
            open_ports, banners, nmap_cpes, discovery_sources, top_cve, top_cvss, first_seen, last_seen, last_scan_id)
           VALUES
           (:ip, :hostname, :mac, :mac_vendor, :category, :vendor, :model, :os_guess, :cpe, :connected_via,
            :open_ports, :banners, :nmap_cpes, :discovery_sources, :top_cve, :top_cvss, datetime('now'), datetime('now'), :job_id)""",
        {**fields, "ip": ip, "job_id": job_id},
    )
    aid = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    return aid, {"is_new": True, "prev_open_ports": None}


def _apply_master_enrichment(conn: sqlite3.Connection, job_id: int) -> tuple[int, int, int, dict[str, int]]:
    """Run AI + CVE enrichment centrally on master for assets from this collector job."""
    jrow = conn.execute("SELECT profile, scan_mode FROM scan_jobs WHERE id=? LIMIT 1", (job_id,)).fetchone()
    scan_profile = str(jrow["profile"] if jrow and jrow["profile"] else "standard_inventory")
    scan_mode = str(jrow["scan_mode"] if jrow and jrow["scan_mode"] else "auto")
    ai_cfg = scanner_daemon._load_ai_enrichment_settings()  # pylint: disable=protected-access
    ai_attempts = 0
    ai_applied = 0
    ai_reason_counts: dict[str, int] = {}
    upserted_assets: list[dict] = []

    rows = conn.execute("SELECT * FROM assets WHERE last_scan_id=? ORDER BY ip ASC", (job_id,)).fetchall()
    for row in rows:
        try:
            ports = json.loads(row["open_ports"] or "[]")
            if not isinstance(ports, list):
                ports = []
        except Exception:
            ports = []
        norm_ports = []
        for p in ports:
            try:
                pi = int(p)
                if 1 <= pi <= 65535:
                    norm_ports.append(pi)
            except Exception:
                continue
        try:
            banners = json.loads(row["banners"] or "{}")
            if not isinstance(banners, dict):
                banners = {}
        except Exception:
            banners = {}
        try:
            nmap_cpes = json.loads(row["nmap_cpes"] or "[]")
            if not isinstance(nmap_cpes, list):
                nmap_cpes = []
        except Exception:
            nmap_cpes = []
        try:
            ds = json.loads(row["discovery_sources"] or "[]")
            if not isinstance(ds, list):
                ds = []
        except Exception:
            ds = []
        try:
            v6 = json.loads(row["ipv6_addrs"] or "[]")
            if not isinstance(v6, list):
                v6 = []
        except Exception:
            v6 = []
        asset = scanner_daemon.upsert_asset(
            job_id=job_id,
            ip=str(row["ip"] or ""),
            mac=str(row["mac"] or ""),
            ports=norm_ports,
            banners=banners,
            nmap_cpes=nmap_cpes,
            http_titles={},
            http_probe="",
            discovery_sources=ds,
            connected_via=str(row["connected_via"] or ""),
            hostname=str(row["hostname"] or ""),
            scan_profile=scan_profile,
            scan_mode=scan_mode,
            ai_cfg=ai_cfg,
            ai_attempts=ai_attempts,
            ipv6_addrs=v6,
            reuse_conn=conn,
        )
        upserted_assets.append(asset)
        if asset.get("_ai_enrichment_attempted"):
            ai_attempts += 1
        if asset.get("_ai_enrichment_applied"):
            ai_applied += 1
        reason = str(asset.get("_ai_enrichment_reason") or "").strip()
        if reason:
            ai_reason_counts[reason] = ai_reason_counts.get(reason, 0) + 1
        # Release writer between assets so Ollama / slow AI does not hold SQLite locked for the whole job.
        conn.commit()

    cve_rows = scanner_daemon.phase_cve(job_id, upserted_assets)
    change_detection.apply_scan_findings_lifecycle(
        conn,
        job_id,
        cve_rows,
        {int(a["id"]) for a in upserted_assets},
    )
    for _si, f in enumerate(cve_rows):
        r0 = conn.execute(
            "SELECT resolved FROM findings WHERE asset_id=? AND cve_id=? LIMIT 1",
            (int(f["asset_id"]), str(f["cve_id"])),
        ).fetchone()
        res = int(r0["resolved"] or 0) if r0 else 0
        conn.execute(
            "INSERT INTO scan_finding_snapshots (job_id, asset_id, cve_id, cvss, severity, resolved) VALUES (?, ?, ?, ?, ?, ?)",
            (
                job_id,
                int(f["asset_id"]),
                str(f["cve_id"]),
                float(f.get("cvss", 0.0) or 0.0),
                str(f.get("severity", "info")),
                res,
            ),
        )
        if (_si + 1) % _INGEST_ROW_COMMIT_INTERVAL == 0:
            conn.commit()
    conn.commit()
    return ai_attempts, ai_applied, len(cve_rows), ai_reason_counts


def process_one(qrow: dict) -> None:
    qid = int(qrow["id"])
    job_id = int(qrow["job_id"])
    rel = str(qrow["local_relpath"] or "")
    path = INGEST_DIR / rel
    if not path.exists():
        raise RuntimeError(f"artifact missing: {rel}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("artifact payload must be object")

    sj = payload.get("scan_job", {}) if isinstance(payload.get("scan_job"), dict) else {}
    job_status = str(sj.get("status", "done"))
    if job_status not in {"done", "failed", "aborted"}:
        job_status = "done"

    # Phase A: apply collector artifact — periodic commits so SQLite does not hold one
    # writer transaction across very large payloads (same spirit as scanner bulk commits).
    asset_map: dict[str, int] = {}
    with db_conn() as conn:
        _a_idx = 0
        for a in payload.get("assets", []) or []:
            if isinstance(a, dict):
                aid, meta = _asset_upsert(conn, job_id, a)
                ip = str(a.get("ip", "")).strip()
                if aid > 0 and ip:
                    asset_map[ip] = aid
                    if meta.get("is_new"):
                        change_detection.insert_change_alert(
                            conn, "new_asset", job_id, asset_id=aid, detail={"ip": ip}
                        )
                    elif meta.get("prev_open_ports") is not None:
                        pl = _coerce_json_list(a.get("open_ports"))
                        change_detection.maybe_alert_port_change(
                            conn, job_id, ip, aid, meta.get("prev_open_ports"), pl
                        )
                if aid > 0:
                    conn.execute(
                        """INSERT INTO scan_asset_snapshots (job_id, asset_id, ip, hostname, category, vendor, top_cve, top_cvss, open_ports)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            job_id, aid, ip, str(a.get("hostname", "")), str(a.get("category", "")),
                            str(a.get("vendor", "")), str(a.get("top_cve", "")), float(a.get("top_cvss", 0.0) or 0.0),
                            json.dumps(_coerce_json_list(a.get("open_ports")), separators=(",", ":"), ensure_ascii=False),
                        ),
                    )
                _a_idx += 1
                if _a_idx % _INGEST_ROW_COMMIT_INTERVAL == 0:
                    conn.commit()

        coll_hint = str(qrow.get("collector_id") or "").strip() or None
        _f_idx = 0
        for f in payload.get("findings", []) or []:
            if not isinstance(f, dict):
                continue
            ip = str(f.get("ip", "")).strip()
            cve = str(f.get("cve_id", "")).strip()
            if ip == "" or cve == "":
                continue
            aid = asset_map.get(ip)
            if not aid:
                row = conn.execute("SELECT id FROM assets WHERE ip=? LIMIT 1", (ip,)).fetchone()
                aid = int(row["id"]) if row else 0
            if aid <= 0:
                continue
            cvss = float(f.get("cvss", 0.0) or 0.0)
            sev = str(f.get("severity", "")) or _severity(cvss)
            tri = finding_triage.build_collector_triage(cvss, collector_id=coll_hint)
            conn.execute(
                """INSERT INTO findings (asset_id, ip, cve_id, cvss, severity, description, published, confirmed_at, resolved,
                     provenance_source, detection_method, confidence, risk_score, evidence_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), ?, ?,?,?,?,?)
                   ON CONFLICT(asset_id, cve_id) DO UPDATE SET
                     cvss=excluded.cvss,
                     severity=excluded.severity,
                     description=excluded.description,
                     published=excluded.published,
                     resolved=excluded.resolved,
                     provenance_source=excluded.provenance_source,
                     detection_method=excluded.detection_method,
                     confidence=excluded.confidence,
                     risk_score=excluded.risk_score,
                     evidence_json=excluded.evidence_json""",
                (
                    aid, ip, cve, cvss, sev, str(f.get("description", ""))[:2000],
                    str(f.get("published", ""))[:64], 1 if int(f.get("resolved", 0) or 0) else 0,
                    tri["provenance_source"],
                    tri["detection_method"],
                    tri["confidence"],
                    tri["risk_score"],
                    tri["evidence_json"],
                ),
            )
            conn.execute(
                "INSERT INTO scan_finding_snapshots (job_id, asset_id, cve_id, cvss, severity, resolved) VALUES (?, ?, ?, ?, ?, ?)",
                (job_id, aid, cve, cvss, sev, 1 if int(f.get("resolved", 0) or 0) else 0),
            )
            _f_idx += 1
            if _f_idx % _INGEST_ROW_COMMIT_INTERVAL == 0:
                conn.commit()

        _l_idx = 0
        for l in payload.get("scan_log", []) or []:
            if not isinstance(l, dict):
                continue
            conn.execute(
                "INSERT INTO scan_log (job_id, ts, level, ip, message) VALUES (?, datetime('now'), ?, ?, ?)",
                (
                    job_id,
                    str(l.get("level", "INFO"))[:8],
                    str(l.get("ip", ""))[:128],
                    str(l.get("message", ""))[:4000],
                ),
            )
            _l_idx += 1
            if _l_idx % _INGEST_ROW_COMMIT_INTERVAL == 0:
                conn.commit()

        _p_idx = 0
        for p in payload.get("port_history", []) or []:
            if not isinstance(p, dict):
                continue
            ip = str(p.get("ip", "")).strip()
            if ip == "":
                continue
            aid = asset_map.get(ip)
            if not aid:
                row = conn.execute("SELECT id FROM assets WHERE ip=? LIMIT 1", (ip,)).fetchone()
                aid = int(row["id"]) if row else 0
            if aid <= 0:
                continue
            conn.execute(
                "INSERT INTO port_history (asset_id, scan_id, ports, seen_at) VALUES (?, ?, ?, datetime('now'))",
                (aid, job_id, json.dumps(_coerce_json_list(p.get("ports")), separators=(",", ":"), ensure_ascii=False)),
            )
            _p_idx += 1
            if _p_idx % _INGEST_ROW_COMMIT_INTERVAL == 0:
                conn.commit()

        conn.execute(
            """UPDATE scan_jobs
               SET hosts_found=COALESCE(?, hosts_found),
                   hosts_scanned=COALESCE(?, hosts_scanned),
                   summary_json=COALESCE(?, summary_json),
                   error_msg=COALESCE(?, error_msg)
               WHERE id=?""",
            (
                int(sj["hosts_found"]) if "hosts_found" in sj else None,
                int(sj["hosts_scanned"]) if "hosts_scanned" in sj else None,
                str(sj["summary_json"]) if "summary_json" in sj else None,
                str(sj["error_msg"]) if "error_msg" in sj else None,
                job_id,
            ),
        )

    # Phase B: CVE/AI (commits after each asset inside _apply_master_enrichment) + queue finalize.
    with db_conn() as conn:
        ai_attempts, ai_applied, cve_count, ai_reason_counts = _apply_master_enrichment(conn, job_id)

        conn.execute(
            "UPDATE collector_ingest_queue SET status='applied', processed_at=datetime('now'), error_msg=NULL WHERE id=?",
            (qid,),
        )
        conn.execute(
            """UPDATE collector_submissions
               SET processed_chunks = (
                 SELECT COUNT(*) FROM collector_ingest_queue q
                 WHERE q.collector_id=collector_submissions.collector_id
                   AND q.job_id=collector_submissions.job_id
                   AND q.submission_id=collector_submissions.submission_id
                   AND q.status='applied'
               ),
                   updated_at=datetime('now')
               WHERE collector_id=? AND job_id=? AND submission_id=?""",
            (int(qrow["collector_id"]), job_id, str(qrow["submission_id"])),
        )
        row = conn.execute(
            "SELECT chunk_count, processed_chunks FROM collector_submissions WHERE collector_id=? AND job_id=? AND submission_id=?",
            (int(qrow["collector_id"]), job_id, str(qrow["submission_id"])),
        ).fetchone()
        if row and int(row["processed_chunks"]) >= int(row["chunk_count"]):
            summary_doc: dict = {}
            try:
                summary_doc = json.loads(str(sj.get("summary_json") or "{}"))
                if not isinstance(summary_doc, dict):
                    summary_doc = {}
            except Exception:
                summary_doc = {}
            summary_doc["collector_central_enrichment"] = True
            summary_doc["ai_enrichment_attempts"] = int(ai_attempts)
            summary_doc["ai_enrichment_applied"] = int(ai_applied)
            summary_doc["ai_reason_counts"] = ai_reason_counts
            summary_doc["collector_cve_matches"] = int(cve_count)
            summary_doc = _master_refresh_scan_executive_summary(summary_doc, job_id)
            conn.execute(
                "UPDATE scan_jobs SET summary_json=? WHERE id=?",
                (json.dumps(summary_doc, separators=(",", ":"), ensure_ascii=False), job_id),
            )
            conn.execute(
                "UPDATE collector_submissions SET status='applied', updated_at=datetime('now') WHERE collector_id=? AND job_id=? AND submission_id=?",
                (int(qrow["collector_id"]), job_id, str(qrow["submission_id"])),
            )
            conn.execute(
                "UPDATE scan_jobs SET status=?, finished_at=COALESCE(finished_at, datetime('now')) WHERE id=? AND status='running'",
                (job_status, job_id),
            )
            conn.execute("DELETE FROM collector_job_leases WHERE job_id=?", (job_id,))


def main() -> None:
    log.info("collector ingest worker started")
    while True:
        try:
            # One queue item per outer attempt: payload vs enrichment are separate transactions;
            # enrichment commits after each asset so AI/Ollama does not hold the writer.
            for _ in range(10):
                row_dict: dict | None = None
                with db_conn() as conn:
                    row = conn.execute(
                        """SELECT *
                           FROM collector_ingest_queue
                           WHERE status IN ('pending','failed')
                             AND (next_attempt_at IS NULL OR next_attempt_at <= datetime('now'))
                           ORDER BY created_at ASC
                           LIMIT 1"""
                    ).fetchone()
                    if row is not None:
                        row_dict = dict(row)
                if row_dict is None:
                    break
                try:
                    process_one(row_dict)
                except Exception as exc:
                    delay = min(300, 5 * (2 ** min(6, int(row_dict.get("attempts") or 0))))
                    with db_conn() as conn:
                        conn.execute(
                            """UPDATE collector_ingest_queue
                               SET status='failed',
                                   attempts=attempts+1,
                                   next_attempt_at=datetime('now', ?),
                                   error_msg=?
                               WHERE id=?""",
                            (f"+{delay} seconds", str(exc)[:600], int(row_dict["id"])),
                        )
                    log.warning("queue item %s failed: %s", int(row_dict["id"]), exc)
        except Exception as outer:
            log.exception("worker loop error: %s", outer)
        time.sleep(POLL_SECS)


if __name__ == "__main__":
    main()
