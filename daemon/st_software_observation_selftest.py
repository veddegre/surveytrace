#!/usr/bin/env python3
"""
Slice 1 — software_observed normalization, dedupe, per-run cap, replace semantics (no network).

Run from repo root:
  python3 daemon/st_software_obs_slice1_selftest.py
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

_DAEMON = Path(__file__).resolve().parent
if str(_DAEMON) not in sys.path:
    sys.path.insert(0, str(_DAEMON))

import recon_observations as recon

DDL = """
CREATE TABLE recon_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_type TEXT NOT NULL,
    source_instance_key TEXT NOT NULL DEFAULT 'default',
    display_name TEXT NOT NULL DEFAULT '',
    trust_level TEXT NOT NULL DEFAULT 'medium',
    freshness_sec INTEGER NOT NULL DEFAULT 86400,
    enabled INTEGER NOT NULL DEFAULT 1,
    meta_json TEXT,
    UNIQUE(source_type, source_instance_key)
);
CREATE TABLE asset_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    asset_id INTEGER NOT NULL,
    observation_type TEXT NOT NULL,
    raw_value TEXT,
    normalized_value TEXT,
    source_id INTEGER NOT NULL REFERENCES recon_sources(id),
    source_object_ref TEXT NOT NULL DEFAULT '',
    observed_at DATETIME NOT NULL DEFAULT (datetime('now')),
    confidence_level TEXT NOT NULL DEFAULT 'medium',
    provenance_json TEXT,
    UNIQUE(asset_id, observation_type, source_id, source_object_ref)
);
"""


def _fail(msg: str) -> None:
    print("FAIL:", msg, file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    sh = recon.normalize_cred_software_shape("Foo\nBar", " 1.0\t", manager="dpkg")
    if sh is None or sh["normalized_name"] != "foobar" or sh["version"] != "1.0":
        _fail("normalize strip / lower")
    if recon.normalize_cred_software_shape("", "1", manager="dpkg") is not None:
        _fail("empty name")

    conn = sqlite3.connect(":memory:")
    conn.executescript(DDL)
    conn.execute(
        "INSERT INTO recon_sources (source_type, source_instance_key, display_name, trust_level, enabled, updated_at) "
        "VALUES ('credentialed_check','default','Cred','high',1,datetime('now'))"
    )

    pk = "ssh.linux.package_inventory"
    pv = "1.0.0"
    pkgs = [
        {"name": "a", "version": "1", "arch": "all"},
        {"name": "a", "version": "1", "arch": "all"},
        {"name": "b", "version": "2", "arch": "all"},
    ]
    n = recon.upsert_cred_software_observations(
        conn,
        asset_id=1,
        packages=pkgs,
        package_manager="dpkg",
        run_id=10,
        target_row_id=20,
        result_id=30,
        plugin_key=pk,
        plugin_version=pv,
        run_partial=False,
        package_count_total=3,
    )
    if n != 2:
        _fail(f"dedupe: expected 2 rows, got {n}")

    many = [{"name": f"p{i}", "version": "1", "arch": "x"} for i in range(300)]
    n2 = recon.upsert_cred_software_observations(
        conn,
        asset_id=1,
        packages=many,
        package_manager="rpm",
        run_id=11,
        target_row_id=21,
        result_id=31,
        plugin_key=pk,
        plugin_version=pv,
        run_partial=False,
        package_count_total=300,
    )
    if n2 != recon.MAX_SOFTWARE_OBS_PER_RUN:
        _fail(f"cap: expected {recon.MAX_SOFTWARE_OBS_PER_RUN}, got {n2}")
    cnt = int(
        conn.execute("SELECT COUNT(*) FROM asset_observations WHERE observation_type='software_observed'").fetchone()[0]
    )
    if cnt != recon.MAX_SOFTWARE_OBS_PER_RUN:
        _fail(f"db row count after cap: expected {recon.MAX_SOFTWARE_OBS_PER_RUN}, got {cnt}")

    row = conn.execute(
        "SELECT raw_value FROM asset_observations WHERE observation_type='software_observed' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if row is None:
        _fail("missing row for partial check")
    doc = json.loads(row[0])
    if doc.get("partial") is not True:
        _fail("partial flag expected True when bounded truncation")

    n3 = recon.upsert_cred_software_observations(
        conn,
        asset_id=1,
        packages=[{"name": "solo", "version": "v", "arch": "a"}],
        package_manager="dpkg",
        run_id=12,
        target_row_id=22,
        result_id=32,
        plugin_key=pk,
        plugin_version=pv,
        run_partial=False,
        package_count_total=1,
    )
    if n3 != 1:
        _fail("replace: expected 1 row written")
    cnt2 = int(
        conn.execute("SELECT COUNT(*) FROM asset_observations WHERE observation_type='software_observed'").fetchone()[0]
    )
    if cnt2 != 1:
        _fail(f"replace: expected 1 remaining row, got {cnt2}")

    doc2 = json.loads(
        conn.execute("SELECT raw_value FROM asset_observations WHERE observation_type='software_observed' LIMIT 1")
        .fetchone()[0]
    )
    if doc2.get("partial") is True:
        _fail("partial flag expected False for full single-package snapshot")

    print("OK st_software_obs_slice1_selftest")


if __name__ == "__main__":
    main()
