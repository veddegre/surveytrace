"""
SurveyTrace — web fingerprint sync utility

Builds a local regex rule set from Wappalyzer technology definitions:
  data/webfp_rules.json

Source (GitHub raw):
  https://raw.githubusercontent.com/developit/wappalyzer/master/src/technologies/{a..z,_.json}
"""

from __future__ import annotations

import json
import logging
import re
import sys
import urllib.request
from pathlib import Path
import sqlite3
from datetime import datetime, timezone

from feed_sync_cancel import cancel_requested

log = logging.getLogger("webfp_sync")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [webfp_sync] %(message)s")

DATA_DIR = Path(__file__).parent.parent / "data"
OUT_PATH = DATA_DIR / "webfp_rules.json"
MAIN_DB_PATH = DATA_DIR / "surveytrace.db"
BASE = "https://raw.githubusercontent.com/developit/wappalyzer/master/src/technologies"
FILES = ["_.json"] + [f"{chr(c)}.json" for c in range(ord("a"), ord("z") + 1)]


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "SurveyTrace/1.0 (+sync_webfp)"})
    with urllib.request.urlopen(req, timeout=90) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _normalize_pattern(pat: str) -> str:
    # Wappalyzer patterns often embed metadata after ';'
    # Example: "WordPress\\;confidence:50\\;version:\\1"
    return pat.split("\\;")[0].strip()


def _yield_patterns(value) -> list[str]:
    if isinstance(value, str):
        return [_normalize_pattern(value)]
    if isinstance(value, list):
        out: list[str] = []
        for v in value:
            if isinstance(v, str):
                out.append(_normalize_pattern(v))
        return out
    return []


def map_category(cats: list[int]) -> str:
    # Conservative mapping to SurveyTrace categories.
    # Unknown categories default to "srv".
    ids = set(int(c) for c in cats if isinstance(c, (int, float, str)) and str(c).isdigit())
    if ids & {5, 22}:  # CDN/network/services-ish
        return "net"
    if ids & {36, 39, 55}:  # IoT / home automation / smart devices in many sets
        return "iot"
    if ids & {4, 6, 9, 11, 18, 31, 32}:  # analytics/cms/ecommerce/web frameworks
        return "srv"
    return "srv"


def build_rules() -> list[dict[str, str]]:
    rules: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for fn in FILES:
        if cancel_requested(DATA_DIR):
            log.info("WebFP sync cancelled — stopping before %s fetch.", fn)
            sys.exit(10)
        url = f"{BASE}/{fn}"
        log.info("Fetching %s", url)
        doc = fetch_json(url)
        for tech_name, info in doc.items():
            if not isinstance(info, dict):
                continue
            cat = map_category(info.get("cats", []))

            # Pull only fields observable in SurveyTrace HTTP probe blob:
            #  - headers (serialized as SERVER=/XPB= lines)
            #  - html/body snippet
            #  - meta (often appears in HTML source)
            for field in ("html", "scripts", "scriptSrc"):
                for pat in _yield_patterns(info.get(field)):
                    if len(pat) < 3:
                        continue
                    key = (tech_name, pat)
                    if key in seen:
                        continue
                    seen.add(key)
                    rules.append({"name": tech_name, "category": cat, "pattern": pat})

            hdr = info.get("headers")
            if isinstance(hdr, dict):
                for hk, hv in hdr.items():
                    for pat in _yield_patterns(hv):
                        if len(pat) < 2:
                            continue
                        # Bind header key and value to reduce false positives.
                        merged = rf"{re.escape(str(hk))}.*{pat}"
                        key = (tech_name, merged)
                        if key in seen:
                            continue
                        seen.add(key)
                        rules.append({"name": tech_name, "category": cat, "pattern": merged})

            meta = info.get("meta")
            if isinstance(meta, dict):
                for mk, mv in meta.items():
                    for pat in _yield_patterns(mv):
                        if len(pat) < 2:
                            continue
                        merged = rf"{re.escape(str(mk))}.*{pat}"
                        key = (tech_name, merged)
                        if key in seen:
                            continue
                        seen.add(key)
                        rules.append({"name": tech_name, "category": cat, "pattern": merged})

    # Keep reasonably bounded and stable
    rules = [r for r in rules if len(r["pattern"]) <= 220]
    return rules


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    rules = build_rules()
    OUT_PATH.write_text(json.dumps({"source": BASE, "rules": rules}, indent=2), encoding="utf-8")
    log.info("Wrote %d web fingerprint rules to %s", len(rules), OUT_PATH)
    try:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        with sqlite3.connect(str(MAIN_DB_PATH)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES ('webfp_last_sync', ?)",
                (now_str,),
            )
            conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES ('webfp_rule_count', ?)",
                (str(len(rules)),),
            )
    except Exception as e:
        log.warning("Could not update config sync metadata: %s", e)


if __name__ == "__main__":
    main()

