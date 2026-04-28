"""
SurveyTrace — NVD feed sync utility
Downloads NVD JSON 2.0 feeds and writes directly into a SQLite database
(data/nvd.db) for fast indexed CVE correlation.

Replaces the old nvd_cpe_map.json approach — lookups go from full JSON
parse (~seconds per asset) to indexed SQLite query (~microseconds).

Usage:
    python3 sync_nvd.py              # full sync
    python3 sync_nvd.py --recent     # only CVEs modified in last 14 days (default)
    python3 sync_nvd.py --days 30    # only CVEs modified in last N days
    python3 sync_nvd.py --migrate    # one-time import of old nvd_cpe_map.json

Schedule via cron for weekly refresh (installed by setup.sh; 14-day window suits weekly runs):
    0 3 * * 0 surveytrace /opt/surveytrace/venv/bin/python3
        /opt/surveytrace/daemon/sync_nvd.py --recent

Get a free NVD API key at nvd.nist.gov/developers/request-an-api-key
SurveyTrace reads the key from (1) NVD_API_KEY environment variable, or
(2) Settings → NVD API key (stored in surveytrace.db), env wins if both are set.

If you still see HTTP 404 on the first page, set NVD_RESULTS_PER_PAGE lower (e.g. 250)
or confirm your API key in Settings / NVD_API_KEY env. The sync auto-halves page size on 404 until 128.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from feed_sync_cancel import cancel_flag_path, cancel_requested

log = logging.getLogger("nvd_sync")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [nvd_sync] %(message)s",
)

# Resolve so cancel flag path matches PHP (ST_DATA_DIR) even if this script is symlinked.
DATA_DIR     = Path(__file__).resolve().parent.parent / "data"
NVD_DB_PATH  = DATA_DIR / "nvd.db"
MAIN_DB_PATH = DATA_DIR / "surveytrace.db"


def sleep_interruptible(total_seconds: float, chunk: float = 0.5) -> None:
    """Sleep up to total_seconds but exit quickly if UI cancel is requested."""
    end = time.monotonic() + max(0.0, total_seconds)
    while time.monotonic() < end:
        if cancel_requested(DATA_DIR):
            log.info("NVD sync cancelled during wait/sleep (UI stop requested).")
            sys.exit(10)
        time.sleep(min(chunk, end - time.monotonic()))

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _load_nvd_api_key_from_db() -> str:
    """Key from Settings UI (config table). Ignored if NVD_API_KEY env is set."""
    if not MAIN_DB_PATH.is_file():
        return ""
    try:
        with sqlite3.connect(str(MAIN_DB_PATH), timeout=10) as conn:
            row = conn.execute(
                "SELECT value FROM config WHERE key = 'nvd_api_key'"
            ).fetchone()
            if row and row[0]:
                return str(row[0]).strip()
    except sqlite3.Error as e:
        log.debug("Could not read nvd_api_key from surveytrace.db: %s", e)
    return ""


def _resolve_nvd_api_key() -> str:
    env_k = (os.environ.get("NVD_API_KEY") or "").strip()
    if env_k:
        return env_k
    return _load_nvd_api_key_from_db()


NVD_API_KEY = _resolve_nvd_api_key()
RATE_SLEEP  = 0.6 if NVD_API_KEY else 6.5


def _results_per_page() -> int:
    # NVD intermittently returns HTTP 404 for large pages; default 500 is conservative.
    try:
        return max(1, min(2000, int(os.environ.get("NVD_RESULTS_PER_PAGE", "500"))))
    except ValueError:
        return 500


RESULTS_PER_PAGE = _results_per_page()

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


def _nvd_api_datetime_utc(dt: datetime) -> str:
    """
    NVD 2.0 requires extended ISO-8601 for lastMod* / pub* parameters, e.g.
    2021-08-04T13:00:00.000Z — NOT the legacy '... UTC+00:00' string (that yields HTTP 404).
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000") + "Z"


def _fetch_page_http(start_index: int, mod_start: str | None, results_per_page: int) -> dict:
    params: dict = {"startIndex": start_index, "resultsPerPage": results_per_page}
    if mod_start:
        params["lastModStartDate"] = mod_start
        params["lastModEndDate"]   = _nvd_api_datetime_utc(datetime.now(timezone.utc))

    url     = NVD_API_BASE + "?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": "SurveyTrace/0.5.0 (self-hosted; +https://github.com/veddegre/surveytrace)"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_page(start_index: int, mod_start: str | None, results_per_page: int) -> dict:
    """
    Run the HTTP fetch in a daemon thread so the main thread can poll the UI
    cancel flag while NIST is slow (otherwise cancel only worked between pages).
    """
    err: list[BaseException] = []
    data: list[dict] = []

    def worker() -> None:
        try:
            data.append(_fetch_page_http(start_index, mod_start, results_per_page))
        except BaseException as e:
            err.append(e)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    while True:
        if cancel_requested(DATA_DIR):
            log.info("NVD sync cancelled during HTTP fetch (UI stop requested).")
            sys.exit(10)
        t.join(0.25)
        if not t.is_alive():
            break
    if err:
        raise err[0]
    return data[0]


def write_batch(conn: sqlite3.Connection, cve_items: list[dict]) -> int:
    written = 0
    for i, item in enumerate(cve_items):
        if i % 25 == 0 and cancel_requested(DATA_DIR):
            log.info("NVD sync cancelled during DB write (%d CVEs written this page so far).", written)
            sys.exit(10)
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


def sync(recent_only: bool = False, days: int = 14) -> None:
    conn = open_nvd_db()

    mod_start: str | None = None
    if recent_only:
        since     = datetime.now(timezone.utc) - timedelta(days=days)
        mod_start = _nvd_api_datetime_utc(since)
        log.info("Incremental sync — CVEs modified since %s", since.date())
    else:
        log.info("Full sync — fetching all CVEs (this takes a while without an API key)")

    start_index   = 0
    total_results = None
    total_written = 0
    page_num      = 0
    fail_streak   = 0
    max_fail_same = 12
    page_size     = RESULTS_PER_PAGE

    log.info(
        "NVD sync: resultsPerPage=%d, api_key=%s, data_dir=%s, cancel_flag=%s",
        page_size,
        "yes" if NVD_API_KEY else "no",
        DATA_DIR,
        cancel_flag_path(DATA_DIR),
    )

    while True:
        if cancel_requested(DATA_DIR):
            log.info("NVD sync cancelled (stop requested from SurveyTrace UI).")
            sys.exit(10)
        page_num += 1
        log.info("Fetching page %d (startIndex %d, resultsPerPage %d)…",
                 page_num, start_index, page_size)
        try:
            data = fetch_page(start_index, mod_start, page_size)
            fail_streak = 0
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                pass
            msg = f"HTTP {e.code}: {e.reason}" + (f" — {detail}" if detail else "")

            if e.code == 404:
                if start_index == 0 and page_size > 128:
                    page_size = max(128, page_size // 2)
                    log.warning(
                        "404 on first page — lowering resultsPerPage to %d and retrying (NVD size limits vary).",
                        page_size,
                    )
                    fail_streak = 0
                    page_num -= 1
                    sleep_interruptible(3)
                    continue
                if start_index == 0:
                    fail_streak += 1
                    log.error(
                        "NVD still returns 404 at startIndex 0 with resultsPerPage=%d. "
                        "Check outbound HTTPS, NVD status, API key in Settings, or NVD_API_KEY env. %s",
                        page_size, msg,
                    )
                    if fail_streak >= max_fail_same:
                        log.error("Aborting after %d failures at startIndex 0.", fail_streak)
                        sys.exit(1)
                    sleep_interruptible(min(30 * fail_streak, 300))
                    continue
                log.warning(
                    "404 at startIndex %d — treating as end of feed (NVD offset limit or empty tail). %s",
                    start_index, msg[:200],
                )
                break

            if e.code in (403, 429, 503):
                fail_streak += 1
                ra = None
                try:
                    if e.headers:
                        ra = e.headers.get("Retry-After")
                except Exception:
                    pass
                try:
                    wait_hdr = int(ra) if ra else 0
                except (TypeError, ValueError):
                    wait_hdr = 0
                wait = max(wait_hdr, min(30 + 30 * fail_streak, 600))
                log.warning("HTTP %s — sleeping %ds (%s)", e.code, wait, msg[:160])
                if fail_streak >= max_fail_same:
                    log.error(
                        "Too many HTTP %s responses — add an API key in Settings (or NVD_API_KEY env): "
                        "https://nvd.nist.gov/developers/request-an-api-key",
                        e.code,
                    )
                    sys.exit(1)
                sleep_interruptible(wait)
                continue

            fail_streak += 1
            log.error("HTTP %s at startIndex %d: %s — retrying in 30s", e.code, start_index, msg[:200])
            if fail_streak >= max_fail_same:
                log.error("Aborting after %d consecutive errors.", fail_streak)
                sys.exit(1)
            sleep_interruptible(30)
            continue
        except Exception as e:
            fail_streak += 1
            log.error("API error at index %d: %s — retrying in 30s", start_index, e)
            if fail_streak >= max_fail_same:
                log.error("Aborting after %d consecutive errors.", fail_streak)
                sys.exit(1)
            sleep_interruptible(30)
            continue

        if total_results is None:
            total_results = int(data.get("totalResults") or 0)
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

        # Advance by actual rows returned (correct for partial last page).
        start_index += len(cve_items)
        if start_index >= total_results:
            break
        sleep_interruptible(RATE_SLEEP)

    if total_results is not None and start_index < total_results:
        log.warning(
            "Stopped before totalResults (%d / %d) — local DB may be incomplete. "
            "Re-run with --recent or set NVD_API_KEY and retry.",
            start_index, total_results,
        )

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
    parser.add_argument("--days",    type=int, default=14,
                        help="Days back for --recent (default: 14)")
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
