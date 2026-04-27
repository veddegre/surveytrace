"""
SurveyTrace — NVD feed sync utility
Downloads NVD JSON 2.0 feeds and writes directly into a SQLite database
(data/nvd.db) for fast indexed CVE correlation.

Replaces the old nvd_cpe_map.json approach — lookups go from full JSON
parse (~seconds per asset) to indexed SQLite query (~microseconds).

Usage:
    python3 sync_nvd.py              # full sync
    python3 sync_nvd.py --recent     # only CVEs modified in last 120 days
    python3 sync_nvd.py --days 30    # only CVEs modified in last N days
    python3 sync_nvd.py --migrate    # one-time import of old nvd_cpe_map.json

Schedule via cron for weekly refresh (installed by setup.sh):
    0 3 * * 0 surveytrace /opt/surveytrace/venv/bin/python3
        /opt/surveytrace/daemon/sync_nvd.py --recent

Get a free NVD API key at nvd.nist.gov/developers/request-an-api-key
Set as NVD_API_KEY env var to raise rate limit 10x.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import time
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("nvd_sync")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [nvd_sync] %(message)s",
)

DATA_DIR     = Path(__file__).parent.parent / "data"
NVD_DB_PATH  = DATA_DIR / "nvd.db"
MAIN_DB_PATH = DATA_DIR / "surveytrace.db"

NVD_API_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY      = os.environ.get("NVD_API_KEY", "")
RATE_SLEEP       = 0.6 if NVD_API_KEY else 6.5
RESULTS_PER_PAGE = 2000

NVD_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;

CREATE TABLE IF NOT EXISTS cves (
    cve_id      TEXT PRIMARY KEY,
    cvss        REAL DEFAULT 0,
    severity    TEXT DEFAULT 'info',
    description TEXT,
    published   TEXT,
    modified    TEXT
);

CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_cvss     ON cves(cvss DESC);

CREATE TABLE IF NOT EXISTS cpe_cve (
    cpe_fragment TEXT NOT NULL,
    cve_id       TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    PRIMARY KEY (cpe_fragment, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_cpe_cve_cpe ON cpe_cve(cpe_fragment);
CREATE INDEX IF NOT EXISTS idx_cpe_cve_cve ON cpe_cve(cve_id);

CREATE TABLE IF NOT EXISTS sync_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def open_nvd_db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(NVD_DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.executescript(NVD_SCHEMA)
    return conn


def cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >  0:   return "low"
    return "info"


def cpe_fragments(uri: str) -> list[str]:
    """
    Convert a full CPE URI to searchable fragments.
    cpe:2.3:h:siemens:s7_1200:2.0:... produces:
      ['cpe:/h:siemens:s7_1200:2.0', 'cpe:/h:siemens:s7_1200', 'cpe:/h:siemens']
    """
    if not uri.startswith("cpe:"):
        return []
    parts = uri.split(":")
    if len(parts) < 5:
        return []
    typ     = parts[2]
    vendor  = parts[3]
    product = parts[4] if len(parts) > 4 else "*"
    version = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-", "") else None

    frags = [
        f"cpe:/{typ}:{vendor}:{product}",
        f"cpe:/{typ}:{vendor}",
    ]
    if version:
        frags.insert(0, f"cpe:/{typ}:{vendor}:{product}:{version}")
    return frags


def parse_cve(item: dict) -> tuple[dict, list[str]]:
    cve_id      = item.get("id", "")
    published   = (item.get("published")    or "")[:10]
    modified    = (item.get("lastModified") or "")[:10]
    description = ""
    for d in item.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    cvss = 0.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = item.get("metrics", {}).get(key)
        if entries:
            try:
                cvss = float(entries[0]["cvssData"]["baseScore"])
                break
            except (KeyError, IndexError, TypeError, ValueError):
                pass

    cpe_set: set[str] = set()
    for config in item.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe_set.update(cpe_fragments(match.get("criteria", "")))

    return {
        "cve_id":      cve_id,
        "cvss":        cvss,
        "severity":    cvss_to_severity(cvss),
        "description": description[:1000],
        "published":   published,
        "modified":    modified,
    }, list(cpe_set)


def fetch_page(start_index: int, mod_start: str | None = None) -> dict:
    params: dict = {"startIndex": start_index, "resultsPerPage": RESULTS_PER_PAGE}
    if mod_start:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000 UTC+00:00")
        params["lastModStartDate"] = mod_start
        params["lastModEndDate"]   = now_str

    url     = NVD_API_BASE + "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": "SurveyTrace/0.4.0 (self-hosted network scanner)"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=90) as resp:
        return json.loads(resp.read())


def write_batch(conn: sqlite3.Connection, cve_items: list[dict]) -> int:
    written = 0
    for item in cve_items:
        cve_row, frags = parse_cve(item)
        if not cve_row["cve_id"]:
            continue
        conn.execute("""
            INSERT INTO cves (cve_id, cvss, severity, description, published, modified)
            VALUES (:cve_id, :cvss, :severity, :description, :published, :modified)
            ON CONFLICT(cve_id) DO UPDATE SET
                cvss=excluded.cvss, severity=excluded.severity,
                description=excluded.description, modified=excluded.modified
        """, cve_row)
        for frag in frags:
            conn.execute(
                "INSERT OR IGNORE INTO cpe_cve (cpe_fragment, cve_id) VALUES (?, ?)",
                (frag, cve_row["cve_id"])
            )
        written += 1
    return written


def update_main_config(now_str: str) -> None:
    try:
        with sqlite3.connect(str(MAIN_DB_PATH)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES ('nvd_last_sync', ?)",
                (now_str,)
            )
    except Exception as e:
        log.warning("Could not update main db config: %s", e)


def sync(recent_only: bool = False, days: int = 120) -> None:
    conn = open_nvd_db()

    mod_start: str | None = None
    if recent_only:
        since     = datetime.now(timezone.utc) - timedelta(days=days)
        mod_start = since.strftime("%Y-%m-%dT%H:%M:%S.000 UTC+00:00")
        log.info("Incremental sync — CVEs modified since %s", since.date())
    else:
        log.info("Full sync — fetching all CVEs (this takes a while without an API key)")

    start_index   = 0
    total_results = None
    total_written = 0
    page_num      = 0

    while True:
        page_num += 1
        log.info("Fetching page %d (index %d)…", page_num, start_index)
        try:
            data = fetch_page(start_index, mod_start)
        except Exception as e:
            log.error("API error at index %d: %s — retrying in 30s", start_index, e)
            time.sleep(30)
            continue

        if total_results is None:
            total_results = data.get("totalResults", 0)
            log.info("Total CVEs in this sync: %d", total_results)

        cve_items = [v.get("cve", {}) for v in data.get("vulnerabilities", [])]
        if not cve_items:
            break

        written        = write_batch(conn, cve_items)
        total_written += written
        conn.commit()

        pct = int(((start_index + len(cve_items)) / max(1, total_results)) * 100)
        log.info("  %d written this page | %d total | %d%%",
                 written, total_written, pct)

        start_index += RESULTS_PER_PAGE
        if start_index >= total_results:
            break
        time.sleep(RATE_SLEEP)

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    conn.execute("INSERT OR REPLACE INTO sync_meta VALUES ('last_sync', ?)", (now_str,))
    conn.execute("INSERT OR REPLACE INTO sync_meta VALUES ('total_cves', ?)", (str(total_written),))
    conn.commit()
    conn.close()
    update_main_config(now_str)

    conn2      = open_nvd_db()
    n_cves     = conn2.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    n_mappings = conn2.execute("SELECT COUNT(*) FROM cpe_cve").fetchone()[0]
    conn2.close()
    log.info("Sync complete — %d CVEs, %d CPE mappings in %s", n_cves, n_mappings, NVD_DB_PATH)


def migrate_json(json_path: Path) -> None:
    """One-time migration from the old nvd_cpe_map.json to SQLite."""
    if not json_path.exists():
        log.info("No nvd_cpe_map.json found at %s — nothing to migrate", json_path)
        return
    log.info("Migrating %s to SQLite (this may take a minute)…", json_path)
    conn  = open_nvd_db()
    count = 0
    with open(json_path) as f:
        cpe_map: dict = json.load(f)
    for cpe_frag, entries in cpe_map.items():
        # Fix malformed fragments from old JSON format
        # old format stored 'cpe:/:a:vendor:product' instead of 'cpe:/a:vendor:product'
        clean_frag = cpe_frag.replace('cpe:/:', 'cpe:/')
        for e in entries:
            cve_id = e.get("cve_id", "")
            if not cve_id:
                continue
            conn.execute("""
                INSERT INTO cves (cve_id, cvss, severity, description, published)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO NOTHING
            """, (cve_id, e.get("cvss", 0), e.get("severity", "info"),
                  e.get("description", ""), e.get("published", "")))
            conn.execute(
                "INSERT OR IGNORE INTO cpe_cve (cpe_fragment, cve_id) VALUES (?, ?)",
                (clean_frag, cve_id)
            )
            count += 1
    conn.commit()
    conn.close()
    log.info("Migration complete — %d CPE→CVE mappings imported", count)
    json_path.rename(json_path.with_suffix(".json.bak"))
    log.info("Old JSON renamed to %s.bak", json_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SurveyTrace NVD sync")
    parser.add_argument("--recent",  action="store_true",
                        help="Incremental: only recently modified CVEs")
    parser.add_argument("--days",    type=int, default=120,
                        help="Days back for --recent (default: 120)")
    parser.add_argument("--migrate", action="store_true",
                        help="Migrate existing nvd_cpe_map.json to SQLite and exit")
    args = parser.parse_args()

    if args.migrate:
        migrate_json(DATA_DIR / "nvd_cpe_map.json")
    else:
        # Auto-migrate old JSON if present and nvd.db doesn't exist yet
        old_json = DATA_DIR / "nvd_cpe_map.json"
        if old_json.exists() and not NVD_DB_PATH.exists():
            log.info("Found existing nvd_cpe_map.json — migrating to SQLite first")
            migrate_json(old_json)
        sync(recent_only=args.recent, days=args.days)
