"""
Persist credentialed package list into normalized software_inventory* tables (SQLite).

Set-based diff for prior active rows; bounded UPDATE ... WHERE id IN (...) batches.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

from software_inventory_normalize import (
    normalize_package_name_fields,
    package_manager_to_ecosystem,
    sanitize_arch,
    sanitize_version_raw,
    version_sidecar_for_row,
)

log = logging.getLogger(__name__)

_ID_BATCH = 400


def software_inventory_tables_ready(conn: sqlite3.Connection) -> bool:
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='software_inventory' LIMIT 1"
        ).fetchone()
        return bool(row)
    except sqlite3.Error:
        return False


def _dedupe_packages(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for row in packages:
        if not isinstance(row, dict):
            continue
        nm = row.get("name")
        ver = row.get("version")
        ar = row.get("arch")
        n = nm if isinstance(nm, str) else str(nm or "")
        v = ver if isinstance(ver, str) else str(ver or "")
        a = ar if isinstance(ar, str) else str(ar or "")
        key = f"{n}\x00{v}\x00{a}"
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": n, "version": v, "arch": a})
    return out


def _get_or_create_inventory_id(
    conn: sqlite3.Connection,
    cache: dict[tuple[str, str], int],
    ecosystem: str,
    canonical_name: str,
    normalized_name: str,
) -> int:
    key = (ecosystem, normalized_name)
    if key in cache:
        return cache[key]
    row = conn.execute(
        "SELECT id FROM software_inventory WHERE ecosystem = ? AND normalized_name = ? LIMIT 1",
        (ecosystem, normalized_name),
    ).fetchone()
    if row:
        iid = int(row[0])
        cache[key] = iid
        conn.execute(
            "UPDATE software_inventory SET canonical_name = ?, updated_at = datetime('now') WHERE id = ?",
            (canonical_name, iid),
        )
        return iid
    conn.execute(
        """INSERT INTO software_inventory (ecosystem, canonical_name, normalized_name, source_package_name, vendor, created_at, updated_at)
               VALUES (?,?,?,?,NULL,datetime('now'),datetime('now'))""",
        (ecosystem, canonical_name, normalized_name, None),
    )
    iid = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    cache[key] = iid
    return iid


def _get_or_create_version_id(
    conn: sqlite3.Connection,
    cache: dict[tuple[int, str, str], int],
    software_inventory_id: int,
    version_raw: str,
    architecture: str,
    eco: str,
) -> int:
    arch = architecture or ""
    key = (software_inventory_id, version_raw, arch)
    if key in cache:
        return cache[key]
    row = conn.execute(
        """SELECT id FROM software_inventory_versions
            WHERE software_inventory_id = ? AND version_raw = ? AND IFNULL(architecture,'') = IFNULL(?,'') LIMIT 1""",
        (software_inventory_id, version_raw, arch if arch else None),
    ).fetchone()
    if row:
        vid = int(row[0])
        cache[key] = vid
        return vid
    side = version_sidecar_for_row(eco, version_raw)
    conn.execute(
        """INSERT INTO software_inventory_versions
            (software_inventory_id, version_raw, version_normalized, architecture, distro_release, package_release, epoch, created_at)
            VALUES (?,?,?,?,?,?,?,datetime('now'))""",
        (
            software_inventory_id,
            version_raw,
            side.get("version_normalized"),
            arch if arch else None,
            side.get("distro_release"),
            side.get("package_release"),
            side.get("epoch"),
        ),
    )
    vid = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    cache[key] = vid
    return vid


def _batch_deactivate_ids(conn: sqlite3.Connection, ids: list[int]) -> None:
    for i in range(0, len(ids), _ID_BATCH):
        chunk = ids[i : i + _ID_BATCH]
        ph = ",".join(["?"] * len(chunk))
        conn.execute(f"UPDATE software_inventory_asset_state SET active = 0 WHERE id IN ({ph})", chunk)


def persist_cred_package_inventory(
    conn: sqlite3.Connection,
    *,
    asset_id: int,
    package_manager: str,
    packages: list[dict[str, Any]],
    credential_check_run_id: int | None,
    plugin_key: str,
    plugin_version: str,
    run_partial: bool,
    package_count_total: int,
) -> dict[str, Any]:
    """
    Upsert normalized rows and flip active flags. Does not commit.

    Returns counts for observation summary (added / removed / version_changed).
    """
    _ = (run_partial, package_count_total)
    out: dict[str, Any] = {
        "ok": False,
        "ecosystem": package_manager_to_ecosystem(package_manager),
        "packages_added": 0,
        "packages_removed": 0,
        "packages_version_changed": 0,
        "active_rows_after": 0,
        "dedupe_input_rows": 0,
    }
    if asset_id < 1 or not software_inventory_tables_ready(conn):
        return out
    eco = out["ecosystem"]
    pk = (plugin_key or "").strip()
    pv = (plugin_version or "").strip()
    if not pk or not pv:
        return out

    rows = _dedupe_packages(packages)
    out["dedupe_input_rows"] = len(rows)

    prev = conn.execute(
        """SELECT st.id, si.id AS inv_id, siv.id AS ver_id
            FROM software_inventory_asset_state st
            INNER JOIN software_inventory_versions siv ON siv.id = st.software_inventory_version_id
            INNER JOIN software_inventory si ON si.id = siv.software_inventory_id
            WHERE st.asset_id = ? AND st.active = 1 AND si.ecosystem = ?""",
        (asset_id, eco),
    ).fetchall()
    prev_by_inv: dict[int, int] = {}
    prev_state_ids: dict[tuple[int, int], int] = {}
    for st_id, inv_id, ver_id in prev:
        iid, vid = int(inv_id), int(ver_id)
        prev_by_inv[iid] = vid
        prev_state_ids[(iid, vid)] = int(st_id)

    desired: dict[int, int] = {}
    inv_cache: dict[tuple[str, str], int] = {}
    ver_cache: dict[tuple[int, str, str], int] = {}

    for pr in rows:
        nf = normalize_package_name_fields(pr["name"])
        if nf is None:
            continue
        canonical_name, normalized_name = nf
        ver_raw = sanitize_version_raw(pr["version"])
        arch = sanitize_arch(pr.get("arch"))
        iid = _get_or_create_inventory_id(conn, inv_cache, eco, canonical_name, normalized_name)
        vid = _get_or_create_version_id(conn, ver_cache, iid, ver_raw, arch, eco)
        desired[iid] = vid

    if not desired and not prev_by_inv:
        out["ok"] = True
        out["active_rows_after"] = 0
        return out

    prev_keys = set(prev_by_inv.keys())
    new_keys = set(desired.keys())
    for inv_id in new_keys - prev_keys:
        out["packages_added"] += 1
    for inv_id in prev_keys - new_keys:
        out["packages_removed"] += 1
    for inv_id in prev_keys & new_keys:
        if prev_by_inv.get(inv_id) != desired.get(inv_id):
            out["packages_version_changed"] += 1

    desired_pairs = {(i, v) for i, v in desired.items()}
    to_deactivate: list[int] = []
    for (iid, vid), sid in prev_state_ids.items():
        if (iid, vid) not in desired_pairs:
            to_deactivate.append(sid)
    if to_deactivate:
        _batch_deactivate_ids(conn, to_deactivate)

    now_run = int(credential_check_run_id) if credential_check_run_id and int(credential_check_run_id) > 0 else None
    for iid, vid in desired.items():
        pair = (iid, vid)
        if pair in prev_state_ids:
            conn.execute(
                """UPDATE software_inventory_asset_state SET active = 1, last_seen_at = datetime('now'),
                    credential_check_run_id = COALESCE(?, credential_check_run_id)
                    WHERE id = ?""",
                (now_run, prev_state_ids[pair]),
            )
            continue
        ex = conn.execute(
            """SELECT id FROM software_inventory_asset_state
                WHERE asset_id = ? AND software_inventory_version_id = ?
                ORDER BY active DESC, last_seen_at DESC, id DESC LIMIT 1""",
            (asset_id, vid),
        ).fetchone()
        if ex:
            conn.execute(
                """UPDATE software_inventory_asset_state SET active = 1, last_seen_at = datetime('now'),
                    credential_check_run_id = COALESCE(?, credential_check_run_id) WHERE id = ?""",
                (now_run, int(ex[0])),
            )
        else:
            conn.execute(
                """INSERT INTO software_inventory_asset_state
                    (asset_id, software_inventory_version_id, first_seen_at, last_seen_at, source, credential_check_run_id, active)
                    VALUES (?,?,datetime('now'),datetime('now'),'credentialed_check',?,1)""",
                (asset_id, vid, now_run),
            )

    crow = conn.execute(
        "SELECT COUNT(*) FROM software_inventory_asset_state WHERE asset_id = ? AND active = 1",
        (asset_id,),
    ).fetchone()
    out["active_rows_after"] = int(crow[0]) if crow else 0
    out["ok"] = True
    return out
