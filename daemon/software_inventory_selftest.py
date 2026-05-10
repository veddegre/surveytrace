#!/usr/bin/env python3
"""Selftest: normalization + SQLite persist + diff semantics (no SurveyTrace DB)."""

from __future__ import annotations

import os
import sqlite3
import sys

# Run from repo root or daemon/
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from software_inventory_normalize import (  # noqa: E402
    normalize_package_name_fields,
    package_manager_to_ecosystem,
    rpm_version_foundation_fields,
    sanitize_version_raw,
)
from software_inventory_persist import (  # noqa: E402
    persist_cred_package_inventory,
    software_inventory_tables_ready,
)


def _fail(msg: str) -> None:
    print("FAIL:", msg, file=sys.stderr)
    sys.exit(1)


def _mk_schema(c: sqlite3.Connection) -> None:
    c.executescript(
        """
        CREATE TABLE assets (id INTEGER PRIMARY KEY);
        CREATE TABLE software_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ecosystem TEXT NOT NULL,
            canonical_name TEXT NOT NULL,
            normalized_name TEXT NOT NULL,
            source_package_name TEXT,
            vendor TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE UNIQUE INDEX uq_software_inventory_eco_norm ON software_inventory(ecosystem, normalized_name);
        CREATE TABLE software_inventory_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            software_inventory_id INTEGER NOT NULL REFERENCES software_inventory(id) ON DELETE CASCADE,
            version_raw TEXT NOT NULL,
            version_normalized TEXT,
            architecture TEXT,
            distro_release TEXT,
            package_release TEXT,
            epoch TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE UNIQUE INDEX uq_software_inventory_versions_key
            ON software_inventory_versions(software_inventory_id, version_raw, IFNULL(architecture, ''));
        CREATE TABLE software_inventory_asset_state (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            software_inventory_version_id INTEGER NOT NULL REFERENCES software_inventory_versions(id) ON DELETE CASCADE,
            first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
            source TEXT NOT NULL DEFAULT 'credentialed_check',
            credential_check_run_id INTEGER,
            active INTEGER NOT NULL DEFAULT 1
        );
        """
    )
    c.execute("INSERT INTO assets (id) VALUES (1)")


def main() -> None:
    nf = normalize_package_name_fields("  OpenSSH/client ")
    if nf is None or nf[1] != "openssh-client":
        _fail(f"normalize_package_name_fields: got {nf!r}")
    if package_manager_to_ecosystem("DPKG") != "dpkg":
        _fail("ecosystem dpkg")
    if package_manager_to_ecosystem("brew") != "generic":
        _fail("ecosystem generic")
    rv = rpm_version_foundation_fields("1:4.4-2.el8")
    if (rv.get("epoch") or "") != "1":
        _fail("rpm epoch")
    if sanitize_version_raw("abc\x00def") != "abcdef":
        _fail("sanitize_version_raw ctrl strip")

    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    _mk_schema(c)
    if not software_inventory_tables_ready(c):
        _fail("tables_ready")

    pkgs = [{"name": "curl", "version": "7.81.0-1", "arch": "amd64"}, {"name": "curl", "version": "7.81.0-1", "arch": "amd64"}]
    d1 = persist_cred_package_inventory(
        c,
        asset_id=1,
        package_manager="dpkg",
        packages=pkgs,
        credential_check_run_id=10,
        plugin_key="ssh.linux.package_inventory",
        plugin_version="1.0.0",
        run_partial=False,
        package_count_total=2,
    )
    if not d1.get("ok") or int(d1.get("packages_added") or 0) != 1 or int(d1.get("active_rows_after") or 0) != 1:
        _fail(f"first persist dedupe+add: {d1!r}")

    d2 = persist_cred_package_inventory(
        c,
        asset_id=1,
        package_manager="dpkg",
        packages=[{"name": "curl", "version": "7.81.0-1", "arch": "amd64"}, {"name": "zlib1g", "version": "1:1.2.11", "arch": "amd64"}],
        credential_check_run_id=11,
        plugin_key="ssh.linux.package_inventory",
        plugin_version="1.0.0",
        run_partial=False,
        package_count_total=2,
    )
    if int(d2.get("packages_added") or 0) != 1 or int(d2.get("packages_removed") or 0) != 0:
        _fail(f"second add zlib: {d2!r}")
    if int(d2.get("active_rows_after") or 0) != 2:
        _fail("active count 2")

    d3 = persist_cred_package_inventory(
        c,
        asset_id=1,
        package_manager="dpkg",
        packages=[{"name": "curl", "version": "8.0.0-1", "arch": "amd64"}, {"name": "zlib1g", "version": "1:1.2.11", "arch": "amd64"}],
        credential_check_run_id=12,
        plugin_key="ssh.linux.package_inventory",
        plugin_version="1.0.0",
        run_partial=False,
        package_count_total=2,
    )
    if int(d3.get("packages_version_changed") or 0) != 1 or int(d3.get("packages_removed") or 0) != 0:
        _fail(f"version bump: {d3!r}")

    d4 = persist_cred_package_inventory(
        c,
        asset_id=1,
        package_manager="dpkg",
        packages=[{"name": "zlib1g", "version": "1:1.2.11", "arch": "amd64"}],
        credential_check_run_id=13,
        plugin_key="ssh.linux.package_inventory",
        plugin_version="1.0.0",
        run_partial=False,
        package_count_total=1,
    )
    if int(d4.get("packages_removed") or 0) != 1 or int(d4.get("active_rows_after") or 0) != 1:
        _fail(f"remove curl: {d4!r}")
    n0 = c.execute(
        "SELECT COUNT(*) FROM software_inventory_asset_state WHERE asset_id=1 AND active=0"
    ).fetchone()[0]
    if int(n0) < 1:
        _fail("expected inactive history row(s)")

    print("OK software_inventory_selftest")


if __name__ == "__main__":
    main()
