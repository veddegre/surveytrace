"""
SurveyTrace — OUI vendor sync utility

Downloads IEEE public MAC assignment registries and builds:
  data/oui_map.json  (AA:BB:CC -> vendor/category)

Sources:
  - https://standards-oui.ieee.org/oui/oui.csv      (MA-L / classic OUI)
  - https://standards-oui.ieee.org/oui28/mam.csv    (MA-M)
  - https://standards-oui.ieee.org/oui36/oui36.csv  (MA-S / OUI-36)
  - https://standards-oui.ieee.org/iab/iab.csv      (IAB)
"""

from __future__ import annotations

import csv
import json
import logging
import re
import sys
import urllib.request
from pathlib import Path
import sqlite3
from datetime import datetime, timezone

from feed_sync_cancel import cancel_requested

log = logging.getLogger("oui_sync")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [oui_sync] %(message)s")

DATA_DIR = Path(__file__).parent.parent / "data"
OUT_PATH = DATA_DIR / "oui_map.json"
MAIN_DB_PATH = DATA_DIR / "surveytrace.db"

SOURCES = [
    ("MA-L", "https://standards-oui.ieee.org/oui/oui.csv"),
    ("MA-M", "https://standards-oui.ieee.org/oui28/mam.csv"),
    ("MA-S", "https://standards-oui.ieee.org/oui36/oui36.csv"),
    ("IAB", "https://standards-oui.ieee.org/iab/iab.csv"),
]


def category_from_vendor(name: str) -> str:
    n = name.lower()
    if re.search(r"cisco|juniper|ubiquiti|aruba|fortinet|mikrotik|netgear|huawei|tp-?link|meraki", n):
        return "net"
    if re.search(r"printer|lexmark|epson|brother|xerox|kyocera|ricoh|hewlett|hp", n):
        return "prn"
    if re.search(r"vmware|proxmox|xen|supermicro|dell|lenovo|intel|asus|gigabyte|server", n):
        return "srv"
    if re.search(r"ring|nest|roku|sonos|tuya|espressif|amazon|google|xiaomi|smart", n):
        return "iot"
    return ""


def normalize_prefix(raw_assignment: str) -> str | None:
    """
    IEEE CSV assignment formats vary by registry:
      - MA-L: 'FCF8AE'
      - MA-M: 'FCF8AE1'
      - MA-S: 'FCF8AE123'
    We normalize to first 24 bits for classic OUI lookup.
    """
    s = "".join(ch for ch in raw_assignment.upper() if ch in "0123456789ABCDEF")
    if len(s) < 6:
        return None
    s = s[:6]
    return f"{s[0:2]}:{s[2:4]}:{s[4:6]}"


def fetch_csv_rows(url: str) -> list[dict[str, str]]:
    req = urllib.request.Request(url, headers={"User-Agent": "SurveyTrace/1.0 (+sync_oui)"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    return list(csv.DictReader(text.splitlines()))


def build_map() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for label, url in SOURCES:
        if cancel_requested(DATA_DIR):
            log.info("OUI sync cancelled — stopping before %s fetch.", label)
            sys.exit(10)
        log.info("Fetching %s from %s", label, url)
        rows = fetch_csv_rows(url)
        for row in rows:
            assignment = row.get("Assignment", "") or row.get("Registry Assignment", "")
            org = (row.get("Organization Name", "") or row.get("Organization", "")).strip()
            prefix = normalize_prefix(assignment)
            if not prefix or not org:
                continue
            # Keep first seen unless we later have a more descriptive name.
            if prefix not in out or len(org) > len(out[prefix].get("vendor", "")):
                out[prefix] = {"vendor": org, "category": category_from_vendor(org)}
        log.info("  %s rows processed: %d", label, len(rows))
    return out


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    oui_map = build_map()
    OUT_PATH.write_text(json.dumps(oui_map, indent=2, sort_keys=True), encoding="utf-8")
    log.info("Wrote %d OUI prefixes to %s", len(oui_map), OUT_PATH)
    try:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        with sqlite3.connect(str(MAIN_DB_PATH)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES ('oui_last_sync', ?)",
                (now_str,),
            )
            conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES ('oui_prefix_count', ?)",
                (str(len(oui_map)),),
            )
    except Exception as e:
        log.warning("Could not update config sync metadata: %s", e)


if __name__ == "__main__":
    main()

