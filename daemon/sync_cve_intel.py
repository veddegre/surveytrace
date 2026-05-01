#!/usr/bin/env python3
"""
SurveyTrace — CVE intelligence feeds (Phase 11)

Ingests complementary *Internet* sources into surveytrace.db (table cve_intel) for
joining with findings at query time:

  1. CISA KEV — Known Exploited Vulnerabilities (authoritative exploited-in-the-wild set)
  2. FIRST EPSS — Exploit prediction scores for CVEs you already have in `findings`
     (downloads the latest daily gzip when available; falls back to FIRST HTTP API)
  3. OSV (api.osv.dev) — cross-ecosystem affected-package hints (Linux distros, Apple/macOS
     where indexed, Android-related ecosystems when present, language ecosystems in
     container images, etc.)

Run from cron after NVD + scans, or from Settings → Sync CVE intel.

Usage:
  python3 sync_cve_intel.py
  python3 sync_cve_intel.py --skip-osv
  python3 sync_cve_intel.py --osv-limit 500
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import logging
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Iterable

from feed_sync_cancel import cancel_requested
from sqlite_pragmas import apply_surveytrace_pragmas
from surveytrace_version import surveytrace_version

log = logging.getLogger("cve_intel_sync")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [cve_intel] %(message)s")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
MAIN_DB_PATH = DATA_DIR / "surveytrace.db"

USER_AGENT = (
    f"SurveyTrace/{surveytrace_version()} cve_intel_sync (+https://github.com/veddegre/surveytrace)"
)

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
EPSS_GZ_URL_TMPL = "https://epss.empiricalsecurity.com/epss_scores-{day}.csv.gz"
FIRST_EPSS_API = "https://api.first.org/data/v1/epss"
OSV_VULN_URL_TMPL = "https://api.osv.dev/v1/vulns/{}"


def sleep_cancelable(total: float, chunk: float = 0.4) -> None:
    end = time.monotonic() + max(0.0, total)
    while time.monotonic() < end:
        if cancel_requested(DATA_DIR):
            log.info("CVE intel sync cancelled (UI stop requested).")
            sys.exit(10)
        time.sleep(min(chunk, end - time.monotonic()))


def http_get_json(url: str, timeout: int = 120) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    return json.loads(raw.decode("utf-8"))


def http_get_bytes(url: str, timeout: int = 180) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def ensure_cve_intel_table(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS cve_intel (
            cve_id            TEXT PRIMARY KEY,
            kev               INTEGER DEFAULT 0,
            kev_date_added    TEXT,
            kev_due_date      TEXT,
            kev_vendor        TEXT,
            kev_product       TEXT,
            kev_action        TEXT,
            epss              REAL,
            epss_percentile   REAL,
            epss_scored_at    TEXT,
            osv_ecosystems    TEXT,
            osv_updated_at    TEXT,
            updated_at        TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_cve_intel_kev ON cve_intel(kev);
        CREATE INDEX IF NOT EXISTS idx_cve_intel_epss ON cve_intel(epss DESC);
        """
    )


def sync_kev(conn: sqlite3.Connection) -> int:
    log.info("Downloading CISA KEV catalog…")
    doc = http_get_json(KEV_URL, timeout=120)
    vulns = doc.get("vulnerabilities")
    if not isinstance(vulns, list):
        log.error("KEV JSON missing vulnerabilities[]")
        return 0
    upsert_sql = """INSERT INTO cve_intel (cve_id, kev, kev_date_added, kev_due_date, kev_vendor, kev_product,
            kev_action, updated_at)
            VALUES (?, 1, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(cve_id) DO UPDATE SET
              kev=1,
              kev_date_added=excluded.kev_date_added,
              kev_due_date=excluded.kev_due_date,
              kev_vendor=excluded.kev_vendor,
              kev_product=excluded.kev_product,
              kev_action=excluded.kev_action,
              updated_at=excluded.updated_at"""
    n = 0
    for row in vulns:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cveID") or row.get("cve_id") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        conn.execute(
            upsert_sql,
            [
                cve,
                str(row.get("dateAdded") or "")[:32],
                str(row.get("dueDate") or "")[:32],
                str(row.get("vendorProject") or "")[:200],
                str(row.get("product") or "")[:200],
                str(row.get("requiredAction") or "")[:500],
            ],
        )
        n += 1
        if n % 200 == 0:
            conn.commit()
            if cancel_requested(DATA_DIR):
                sys.exit(10)
    conn.commit()
    log.info("KEV upsert complete (%d rows from catalog)", n)
    return n


def findings_cve_set(conn: sqlite3.Connection, limit: int) -> list[str]:
    cur = conn.execute(
        "SELECT DISTINCT UPPER(TRIM(cve_id)) AS c FROM findings WHERE cve_id IS NOT NULL AND TRIM(cve_id) != '' LIMIT ?",
        (int(limit),),
    )
    out = [str(r[0]) for r in cur.fetchall() if r and r[0]]
    return sorted(set(out))


def sync_epss_from_gzip(conn: sqlite3.Connection, wanted: set[str], gz_bytes: bytes, scored_at: str) -> int:
    buf = gzip.GzipFile(fileobj=io.BytesIO(gz_bytes), mode="rb")
    text = io.TextIOWrapper(buf, encoding="utf-8", errors="replace")
    line_no = 0
    n = 0
    batch: list[tuple[str, float, float, str]] = []
    epss_sql = """INSERT INTO cve_intel (cve_id, epss, epss_percentile, epss_scored_at, updated_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            ON CONFLICT(cve_id) DO UPDATE SET
              epss=excluded.epss,
              epss_percentile=excluded.epss_percentile,
              epss_scored_at=excluded.epss_scored_at,
              updated_at=excluded.updated_at"""
    for line in text:
        line_no += 1
        if line_no == 1 and line.lower().startswith("cve"):
            continue
        parts = line.strip().split(",")
        if len(parts) < 3:
            continue
        cve = parts[0].strip().upper()
        if cve not in wanted:
            continue
        try:
            epss = float(parts[1])
            pct = float(parts[2])
        except (TypeError, ValueError):
            continue
        batch.append((cve, epss, pct, scored_at))
        if len(batch) >= 500:
            for row in batch:
                conn.execute(epss_sql, list(row))
            n += len(batch)
            batch.clear()
            conn.commit()
            if cancel_requested(DATA_DIR):
                sys.exit(10)
    for row in batch:
        conn.execute(epss_sql, list(row))
    n += len(batch)
    conn.commit()
    return n


def sync_epss_via_first_api(conn: sqlite3.Connection, cves: list[str], scored_at: str) -> int:
    """Fallback when gzip is unavailable: batched FIRST EPSS API (public)."""
    n = 0
    chunk_size = 35
    for i in range(0, len(cves), chunk_size):
        if cancel_requested(DATA_DIR):
            sys.exit(10)
        chunk = cves[i : i + chunk_size]
        q = urllib.parse.urlencode({"cve": ",".join(chunk)})
        url = f"{FIRST_EPSS_API}?{q}"
        try:
            doc = http_get_json(url, timeout=90)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            log.warning("FIRST EPSS API chunk failed: %s", e)
            sleep_cancelable(1.0)
            continue
        rows = doc.get("data") if isinstance(doc, dict) else None
        if not isinstance(rows, list):
            continue
        epss_sql = """INSERT INTO cve_intel (cve_id, epss, epss_percentile, epss_scored_at, updated_at)
                VALUES (?, ?, ?, ?, datetime('now'))
                ON CONFLICT(cve_id) DO UPDATE SET
                  epss=excluded.epss,
                  epss_percentile=excluded.epss_percentile,
                  epss_scored_at=excluded.epss_scored_at,
                  updated_at=excluded.updated_at"""
        for r in rows:
            if not isinstance(r, dict):
                continue
            cve = str(r.get("cve") or "").strip().upper()
            if not cve.startswith("CVE-"):
                continue
            try:
                epss = float(r.get("epss"))
                pct = float(r.get("percentile"))
            except (TypeError, ValueError):
                continue
            conn.execute(epss_sql, [cve, epss, pct, scored_at])
            n += 1
        conn.commit()
        sleep_cancelable(0.55)
    return n


def sync_epss(conn: sqlite3.Connection, wanted_list: list[str]) -> int:
    wanted = set(wanted_list)
    if not wanted:
        log.info("No findings CVE ids — skipping EPSS import.")
        return 0
    scored_at = date.today().isoformat()
    for i in range(14):
        if cancel_requested(DATA_DIR):
            sys.exit(10)
        day = (date.today() - timedelta(days=i)).isoformat()
        url = EPSS_GZ_URL_TMPL.format(day=day)
        try:
            log.info("Trying EPSS gzip %s", url)
            gz = http_get_bytes(url, timeout=180)
            n = sync_epss_from_gzip(conn, wanted, gz, scored_at)
            log.info("EPSS import from gzip: %d rows (day %s)", n, day)
            return n
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            log.warning("EPSS gzip HTTP error %s for %s", e.code, day)
        except (urllib.error.URLError, TimeoutError, OSError, gzip.BadGzipFile) as e:
            log.warning("EPSS gzip failed (%s) for %s", e, day)
    log.info("EPSS gzip not found for recent days — using FIRST API fallback (slower).")
    return sync_epss_via_first_api(conn, wanted_list, scored_at)


def extract_osv_ecosystems(doc: dict[str, Any]) -> str:
    eco: set[str] = set()
    for aff in doc.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package")
        if isinstance(pkg, dict):
            e = str(pkg.get("ecosystem") or "").strip()
            n = str(pkg.get("name") or "").strip()
            if e:
                eco.add(e if not n else f"{e}:{n}"[:120])
    lst = sorted(eco)[:48]
    return json.dumps(lst, separators=(",", ":"), ensure_ascii=False)


def sync_osv(conn: sqlite3.Connection, cves: Iterable[str], limit: int) -> int:
    osv_sql = """INSERT INTO cve_intel (cve_id, osv_ecosystems, osv_updated_at, updated_at)
            VALUES (?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(cve_id) DO UPDATE SET
              osv_ecosystems=excluded.osv_ecosystems,
              osv_updated_at=excluded.osv_updated_at,
              updated_at=excluded.updated_at"""
    n = 0
    for cve in cves:
        if n >= limit:
            break
        if cancel_requested(DATA_DIR):
            sys.exit(10)
        cve = str(cve).strip().upper()
        if not cve.startswith("CVE-"):
            continue
        url = OSV_VULN_URL_TMPL.format(cve)
        try:
            raw = http_get_bytes(url, timeout=45)
            doc = json.loads(raw.decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                sleep_cancelable(0.08)
                continue
            log.debug("OSV HTTP %s for %s", e.code, cve)
            sleep_cancelable(0.3)
            continue
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            log.debug("OSV skip %s: %s", cve, e)
            sleep_cancelable(0.2)
            continue
        if not isinstance(doc, dict) or not doc.get("id"):
            continue
        eco_json = extract_osv_ecosystems(doc)
        conn.execute(osv_sql, [cve, eco_json])
        n += 1
        if n % 50 == 0:
            conn.commit()
        sleep_cancelable(0.12)
    conn.commit()
    log.info("OSV ecosystem hints stored for %d CVEs (cap %d)", n, limit)
    return n


def write_last_sync(conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('cve_intel_last_sync', datetime('now'))"
    )
    conn.commit()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-kev", action="store_true")
    ap.add_argument("--skip-epss", action="store_true")
    ap.add_argument("--skip-osv", action="store_true")
    ap.add_argument("--osv-limit", type=int, default=2000, help="Max OSV API lookups per run")
    ap.add_argument("--findings-cve-cap", type=int, default=25000, help="Max distinct findings.cve_id for EPSS")
    args = ap.parse_args()

    if not MAIN_DB_PATH.is_file():
        log.error("surveytrace.db not found at %s", MAIN_DB_PATH)
        sys.exit(1)

    conn = sqlite3.connect(str(MAIN_DB_PATH), timeout=60)
    try:
        apply_surveytrace_pragmas(conn)
        ensure_cve_intel_table(conn)

        if not args.skip_kev:
            sync_kev(conn)
        else:
            log.info("Skipping KEV (--skip-kev)")

        cve_list = findings_cve_set(conn, args.findings_cve_cap)
        log.info("Distinct CVE ids from findings (capped): %d", len(cve_list))

        if not args.skip_epss:
            sync_epss(conn, cve_list)
        else:
            log.info("Skipping EPSS (--skip-epss)")

        if not args.skip_osv:
            sync_osv(conn, cve_list, max(0, int(args.osv_limit)))
        else:
            log.info("Skipping OSV (--skip-osv)")

        write_last_sync(conn)
        log.info("CVE intel sync finished OK.")
    finally:
        conn.close()


if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        raise e
    except Exception as e:
        log.exception("CVE intel sync failed: %s", e)
        sys.exit(1)
