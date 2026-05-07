"""
SurveyTrace — best-effort OS/platform observation rows for reconciliation (Milestone 1 slice 2).

Normalization mirrors api/lib_reconciliation.php (st_recon_normalize_os_text / st_recon_normalize_os_cpe).
Keep in sync when extending OS buckets.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from typing import Any

log = logging.getLogger(__name__)

_OS_TEXT_PATTERNS = (
    (re.compile(r"windows\s*server\s*2025", re.I), "windows_server_2025", "Windows Server 2025"),
    (re.compile(r"windows\s*server\s*2022", re.I), "windows_server_2022", "Windows Server 2022"),
    (re.compile(r"windows\s*server\s*2019", re.I), "windows_server_2019", "Windows Server 2019"),
    (re.compile(r"windows\s*server\s*2016", re.I), "windows_server_2016", "Windows Server 2016"),
    (re.compile(r"windows\s*11", re.I), "windows_11", "Windows 11"),
    (re.compile(r"windows\s*10", re.I), "windows_10", "Windows 10"),
)


def _normalize_os_text(raw: str) -> tuple[str, str] | None:
    s = (raw or "").strip()
    if not s:
        return None
    low = s.lower()
    for rx, slug, label in _OS_TEXT_PATTERNS:
        if rx.search(s):
            return slug, label
    if "windows" in low:
        return "windows_unknown", "Windows"
    m = re.search(r"ubuntu[^\d]*(\d+)\.(\d+)", s, re.I)
    if m:
        maj, mn = int(m.group(1)), int(m.group(2))
        return f"ubuntu_{maj}_{mn}_x", f"Ubuntu {maj}.{mn}.x"
    m = re.search(r"ubuntu[^\d]*(\d+)", s, re.I)
    if m:
        maj = int(m.group(1))
        return f"ubuntu_{maj}_x", f"Ubuntu {maj}.x"
    if "ubuntu" in low:
        return "ubuntu_unknown", "Ubuntu"
    m = re.search(r"debian[^\d]*(\d+)", s, re.I)
    if m:
        v = int(m.group(1))
        return f"debian_{v}_x", f"Debian {v}.x"
    if "debian" in low:
        return "debian_unknown", "Debian"
    m = re.search(r"red\s*hat[^\d]*(\d+)", s, re.I) or re.search(r"\brhel[^\d]*(\d+)", s, re.I)
    if m:
        v = int(m.group(1))
        return f"rhel_{v}_x", f"RHEL {v}.x"
    m = re.search(r"centos[^\d]*(\d+)", s, re.I)
    if m:
        v = int(m.group(1))
        return f"centos_{v}_x", f"CentOS {v}.x"
    if "rocky" in low or "alma" in low:
        return "enterprise_linux_unknown", "Enterprise Linux"
    if "linux" in low:
        return "linux_unknown", "Linux"
    if "esxi" in low or "vmware" in low:
        return "vmware_esxi_unknown", "VMware ESXi"
    return "os_unknown", s.strip()


def _normalize_os_cpe(cpe: str) -> tuple[str, str] | None:
    c = (cpe or "").strip()
    if not c:
        return None
    m = re.match(r"^cpe:2\.3:o:([^:]+):([^:]+):([^:]*)", c, re.I)
    if not m:
        return None
    vendor = (m.group(1) or "").lower()
    product = (m.group(2) or "").lower()
    ver = (m.group(3) or "").lower()
    if ver in ("*", "-", ""):
        ver = ""
    if ("canonical" in vendor or "ubuntu" in product) and ver:
        vm = re.match(r"^(\d+)\.(\d+)", ver)
        if vm:
            maj, mn = int(vm.group(1)), int(vm.group(2))
            return f"ubuntu_{maj}_{mn}_x", f"Ubuntu {maj}.{mn}.x"
    if vendor == "microsoft":
        prod_label = product.replace("_", " ")
        slug = "windows_unknown"
        if "windows_server" in product:
            slug = re.sub(r"[^a-z0-9]+", "_", "windows_" + product).strip("_") or "windows_unknown"
        elif "windows" in product:
            slug = re.sub(r"[^a-z0-9]+", "_", product).strip("_") or "windows_unknown"
        if ver:
            vs = re.sub(r"[^0-9a-z.]+", "_", ver, flags=re.I).strip("_")
            return f"{slug}_{vs}" if vs else slug, prod_label.title() + " " + ver
        return slug, prod_label.title()
    slug = re.sub(r"[^a-z0-9]+", "_", f"{vendor}_{product}_{ver}".strip("_")).strip("_")
    if not slug:
        return None
    label = (vendor + " " + product.replace("_", " ")).title()
    if ver:
        label += " " + ver
    return slug, label


def _recon_tables_ready(cur: sqlite3.Cursor) -> bool:
    try:
        row = cur.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='recon_sources' LIMIT 1"
        ).fetchone()
        return bool(row)
    except sqlite3.Error:
        return False


def _recon_seed_sources(conn: sqlite3.Connection) -> None:
    rows = (
        ("surveytrace_scan", "SurveyTrace scan", "high"),
        ("zabbix_inventory", "Zabbix inventory", "high"),
        ("surveytrace_enrichment", "SurveyTrace enrichment", "medium"),
        ("credentialed_check", "Credentialed check worker", "high"),
    )
    for stype, disp, trust in rows:
        conn.execute(
            "INSERT OR IGNORE INTO recon_sources (source_type, source_instance_key, display_name, trust_level, enabled, updated_at) "
            "VALUES (?, 'default', ?, ?, 1, datetime('now'))",
            (stype, disp, trust),
        )


def _recon_source_id(conn: sqlite3.Connection, source_type: str) -> int | None:
    row = conn.execute(
        "SELECT id FROM recon_sources WHERE source_type = ? AND source_instance_key = 'default' LIMIT 1",
        (source_type,),
    ).fetchone()
    if not row:
        return None
    return int(row[0])


def _upsert_observation(
    conn: sqlite3.Connection,
    asset_id: int,
    obs_type: str,
    raw_value: str,
    norm_value: str,
    source_id: int,
    source_ref: str,
    confidence: str,
    provenance_json: str,
) -> None:
    conn.execute(
        """
        INSERT INTO asset_observations (asset_id, observation_type, raw_value, normalized_value, source_id,
            source_object_ref, observed_at, confidence_level, provenance_json)
        VALUES (?,?,?,?,?,?,datetime('now'),?,?)
        ON CONFLICT(asset_id, observation_type, source_id, source_object_ref) DO UPDATE SET
            raw_value = excluded.raw_value,
            normalized_value = excluded.normalized_value,
            confidence_level = excluded.confidence_level,
            provenance_json = excluded.provenance_json,
            observed_at = CASE
                WHEN asset_observations.raw_value = excluded.raw_value
                 AND asset_observations.normalized_value = excluded.normalized_value
                THEN asset_observations.observed_at
                ELSE datetime('now')
            END
        """,
        (asset_id, obs_type, raw_value, norm_value, source_id, source_ref, confidence, provenance_json),
    )


def normalize_os_text_public(raw: str) -> tuple[str, str]:
    """Deterministic OS slug + label; aligned with api/lib_reconciliation.php buckets."""
    n = _normalize_os_text(raw)
    if n is None:
        return "os_unknown", ""
    return n[0], n[1]


def upsert_credentialed_check_os_observation(
    conn: sqlite3.Connection,
    *,
    asset_id: int,
    raw_value: str,
    source_object_ref: str,
    provenance: dict[str, Any],
) -> bool:
    """
    os_version_observed from credentialed_check source. Idempotent on UNIQUE(asset_id, type, source_id, ref).
    Returns True if a row was written/updated.
    """
    if asset_id < 1 or not _recon_tables_ready(conn):
        return False
    try:
        _recon_seed_sources(conn)
        sid = _recon_source_id(conn, "credentialed_check")
        if sid is None:
            return False
        slug, label = normalize_os_text_public(raw_value)
        norm_val = slug if slug else "os_unknown"
        prov = json.dumps(provenance, separators=(",", ":"), ensure_ascii=False)
        raw_safe = (raw_value or "")[:4000]
        _upsert_observation(
            conn,
            asset_id,
            "os_version_observed",
            raw_safe,
            norm_val,
            sid,
            source_object_ref[:500] if source_object_ref else "",
            "high",
            prov if prov else "{}",
        )
        return True
    except sqlite3.Error:
        return False


def upsert_cred_package_inventory_summary_observation(
    conn: sqlite3.Connection,
    *,
    asset_id: int,
    raw_value: str,
    normalized_value: str,
    source_object_ref: str,
    provenance: dict[str, Any],
) -> bool:
    """
    Summarized package_inventory_observed from credentialed_check (manager / count / digest).
    Does not create per-package asset_observations rows (bounded volume).
    """
    if asset_id < 1 or not _recon_tables_ready(conn):
        return False
    try:
        _recon_seed_sources(conn)
        sid = _recon_source_id(conn, "credentialed_check")
        if sid is None:
            return False
        prov = json.dumps(provenance, separators=(",", ":"), ensure_ascii=False)
        raw_safe = (raw_value or "")[:4000]
        norm_safe = (normalized_value or "")[:500]
        _upsert_observation(
            conn,
            asset_id,
            "package_inventory_observed",
            raw_safe,
            norm_safe,
            sid,
            source_object_ref[:500] if source_object_ref else "",
            "medium",
            prov if prov else "{}",
        )
        return True
    except sqlite3.Error:
        return False


# --- Software inventory observations (slice 1: bounded software_observed; no CVE / assertions) ---

# Aligned with cred_check_run MAX_PKG_ROWS_STORE field caps; keep observation JSON small.
_SOFTWARE_OBS_NAME_MAX = 200
_SOFTWARE_OBS_VER_MAX = 200
MAX_SOFTWARE_OBS_PER_RUN = 128

_FIELD_SAFE_SW = re.compile(r"[^\x20-\x7E]+")
_CTRL_SW = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def normalize_cred_software_manager(package_manager: str) -> str:
    x = (package_manager or "").strip().lower()
    return x if x in ("dpkg", "rpm") else "unknown"


def normalize_cred_software_shape(
    name: str,
    version: str,
    *,
    manager: str,
) -> dict[str, Any] | None:
    """
    Bounded JSON shape for software_observed raw_value (no semver / CPE / vendor inference).
    Returns None when package name is empty after sanitization.
    Caller adds ``partial`` when emitting storage JSON.
    """
    n = _CTRL_SW.sub("", (name or "").strip())
    n = _FIELD_SAFE_SW.sub("", n)[:_SOFTWARE_OBS_NAME_MAX]
    if not n:
        return None
    v = _CTRL_SW.sub("", (version or "").strip())
    v = _FIELD_SAFE_SW.sub("", v)[:_SOFTWARE_OBS_VER_MAX]
    mgr = normalize_cred_software_manager(manager)
    nn = n.lower()[:_SOFTWARE_OBS_NAME_MAX]
    return {
        "name": n,
        "normalized_name": nn,
        "version": v,
        "manager": mgr,
        "source": "credentialed_check",
    }


def _cred_software_norm_fingerprint(shape: dict[str, Any]) -> str:
    """Stable compact fingerprint for normalized_value column (≤500)."""
    nn = str(shape.get("normalized_name") or "")
    ver = str(shape.get("version") or "")
    mgr = str(shape.get("manager") or "")
    return f"{mgr}|{nn}|{ver}"[:500]


def delete_cred_software_observations_for_asset_plugin(
    conn: sqlite3.Connection,
    *,
    asset_id: int,
    source_id: int,
    plugin_key: str,
) -> None:
    """Remove prior bounded software slice rows for this asset + plugin (latest run replaces evidence set)."""
    pk = (plugin_key or "").strip()
    if asset_id < 1 or source_id < 1 or not pk:
        return
    conn.execute(
        """DELETE FROM asset_observations
            WHERE asset_id = ? AND observation_type = 'software_observed' AND source_id = ?
              AND COALESCE(json_extract(provenance_json, '$.plugin_key'), '') = ?""",
        (asset_id, source_id, pk),
    )


def upsert_cred_software_observations(
    conn: sqlite3.Connection,
    *,
    asset_id: int,
    packages: list[dict[str, Any]],
    package_manager: str,
    run_id: int,
    target_row_id: int,
    result_id: int,
    plugin_key: str,
    plugin_version: str,
    run_partial: bool,
    package_count_total: int,
) -> int:
    """
    Insert up to MAX_SOFTWARE_OBS_PER_RUN software_observed rows for one package_inventory result.

    Dedupes by (normalized_name, version, manager) within this run. Deletes prior rows for the same
    asset + credentialed_check source + plugin_key so per-host storage stays bounded by the cap
    (latest successful inventory replaces the bounded preview set).

    Does not write asset_assertions. Returns rows inserted.
    """
    if asset_id < 1 or not _recon_tables_ready(conn):
        return 0
    mgr_in = normalize_cred_software_manager(package_manager)
    if mgr_in == "unknown":
        return 0
    pk = (plugin_key or "").strip()
    pv = (plugin_version or "").strip()
    if not pk or not pv:
        return 0

    unique_ordered: list[dict[str, Any]] = []
    dedupe_seen: set[str] = set()
    for row in packages:
        if not isinstance(row, dict):
            continue
        nm_raw = row.get("name")
        ver_raw = row.get("version")
        nm = nm_raw if isinstance(nm_raw, str) else str(nm_raw or "")
        ver = ver_raw if isinstance(ver_raw, str) else str(ver_raw or "")
        shape = normalize_cred_software_shape(nm, ver, manager=mgr_in)
        if shape is None:
            continue
        dk = f"{shape['manager']}\x00{shape['normalized_name']}\x00{shape['version']}"
        if dk in dedupe_seen:
            continue
        dedupe_seen.add(dk)
        unique_ordered.append(shape)

    ordered_unique = unique_ordered[:MAX_SOFTWARE_OBS_PER_RUN]
    bounded_trunc = len(unique_ordered) > MAX_SOFTWARE_OBS_PER_RUN
    batch_partial = bool(run_partial or bounded_trunc)

    try:
        _recon_seed_sources(conn)
        sid = _recon_source_id(conn, "credentialed_check")
        if sid is None:
            return 0

        delete_cred_software_observations_for_asset_plugin(conn, asset_id=asset_id, source_id=sid, plugin_key=pk)

        if not ordered_unique:
            return 0

        written = 0
        base_ref = f"run:{run_id}:target:{target_row_id}:{pk}@{pv}"
        for i, shape in enumerate(ordered_unique):
            raw_doc = {**shape, "partial": batch_partial}
            raw_json = json.dumps(raw_doc, separators=(",", ":"), ensure_ascii=False)
            raw_safe = raw_json[:4000]
            norm_safe = _cred_software_norm_fingerprint(shape)
            ref = f"{base_ref}:sw:{i}"[:500]
            base_prov: dict[str, Any] = {
                "plugin_key": pk,
                "plugin_version": pv,
                "run_id": run_id,
                "target_row_id": target_row_id,
                "result_id": result_id,
            }
            if i == 0:
                base_prov["aggregate_package_count"] = int(package_count_total)
                base_prov["software_obs_cap"] = MAX_SOFTWARE_OBS_PER_RUN
                base_prov["dedupe_unique_packages"] = len(unique_ordered)
                base_prov["rows_written_planned"] = len(ordered_unique)
                base_prov["bounded_truncation"] = bool(bounded_trunc)
            prov = json.dumps(base_prov, separators=(",", ":"), ensure_ascii=False)
            _upsert_observation(
                conn,
                asset_id,
                "software_observed",
                raw_safe,
                norm_safe,
                sid,
                ref,
                "medium",
                prov if prov else "{}",
            )
            written += 1
        return written
    except sqlite3.Error:
        return 0


def upsert_cred_snmp_sysname_observations(
    conn: sqlite3.Connection,
    *,
    asset_id: int,
    sys_name: str,
    run_id: int,
    target_row_id: int,
    plugin_key: str,
    plugin_version: str,
    result_id: int,
) -> bool:
    """
    hostname_observed (+ fqdn_observed when sysName looks like FQDN) from SNMP sysName.
    Idempotent per (asset_id, type, credentialed_check source, unique source_object_ref suffix).
    """
    if asset_id < 1 or not _recon_tables_ready(conn):
        return False
    s = (sys_name or "").strip()
    if not s:
        return False
    try:
        _recon_seed_sources(conn)
        sid = _recon_source_id(conn, "credentialed_check")
        if sid is None:
            return False
        base_ref = f"run:{run_id}:target:{target_row_id}:{plugin_key}@{plugin_version}"
        prov_core = {
            "plugin_key": plugin_key,
            "plugin_version": plugin_version,
            "run_id": run_id,
            "target_row_id": target_row_id,
            "result_id": result_id,
        }
        low = s.lower().rstrip(".")
        if len(low) > 512:
            return False
        wrote = False
        if "." in low:
            short = low.split(".", 1)[0]
            if short and short != low:
                fqdn_prov = json.dumps({**prov_core, "field": "sysName", "origin": "credentialed_check"}, separators=(",", ":"))
                hn_prov = json.dumps(
                    {**prov_core, "field": "sysName", "derived_from": "fqdn", "origin": "credentialed_check"},
                    separators=(",", ":"),
                )
                _upsert_observation(
                    conn,
                    asset_id,
                    "fqdn_observed",
                    s[:4000],
                    low[:512],
                    sid,
                    f"{base_ref}:fqdn"[:500],
                    "medium",
                    fqdn_prov if fqdn_prov else "{}",
                )
                _upsert_observation(
                    conn,
                    asset_id,
                    "hostname_observed",
                    s[:4000],
                    short[:512],
                    sid,
                    f"{base_ref}:hostname_short"[:500],
                    "medium",
                    hn_prov if hn_prov else "{}",
                )
                wrote = True
            else:
                prov = json.dumps({**prov_core, "field": "sysName", "origin": "credentialed_check"}, separators=(",", ":"))
                _upsert_observation(
                    conn,
                    asset_id,
                    "hostname_observed",
                    s[:4000],
                    low[:512],
                    sid,
                    f"{base_ref}:hostname"[:500],
                    "medium",
                    prov if prov else "{}",
                )
                wrote = True
        else:
            prov = json.dumps({**prov_core, "field": "sysName", "origin": "credentialed_check"}, separators=(",", ":"))
            _upsert_observation(
                conn,
                asset_id,
                "hostname_observed",
                s[:4000],
                low[:512],
                sid,
                f"{base_ref}:hostname"[:500],
                "medium",
                prov if prov else "{}",
            )
            wrote = True
        return wrote
    except sqlite3.Error:
        return False


def upsert_cred_device_identity_summary_observation(
    conn: sqlite3.Connection,
    *,
    asset_id: int,
    normalized_digest: str,
    raw_summary_json: str,
    source_object_ref: str,
    provenance: dict[str, Any],
) -> bool:
    """Summarized device_identity_observed from SNMP cred check (no per-OID explosion)."""
    if asset_id < 1 or not _recon_tables_ready(conn):
        return False
    try:
        _recon_seed_sources(conn)
        sid = _recon_source_id(conn, "credentialed_check")
        if sid is None:
            return False
        prov = json.dumps(provenance, separators=(",", ":"), ensure_ascii=False)
        raw_safe = (raw_summary_json or "")[:4000]
        norm_safe = (normalized_digest or "")[:500]
        _upsert_observation(
            conn,
            asset_id,
            "device_identity_observed",
            raw_safe,
            norm_safe,
            sid,
            source_object_ref[:500] if source_object_ref else "",
            "medium",
            prov if prov else "{}",
        )
        return True
    except sqlite3.Error:
        return False


def write_scan_os_observations_best_effort(
    conn: sqlite3.Connection,
    asset_id: int,
    os_guess: str,
    cpe: str,
    discovery_sources: Any,
) -> None:
    """Persist scan-side OS observations; never raises to callers."""
    if asset_id <= 0 or not _recon_tables_ready(conn):
        return
    try:
        _recon_seed_sources(conn)
        sid_scan = _recon_source_id(conn, "surveytrace_scan")
        sid_enr = _recon_source_id(conn, "surveytrace_enrichment")
        if sid_scan is None or sid_enr is None:
            return
        og = (os_guess or "").strip()
        if og:
            norm = _normalize_os_text(og)
            if norm and norm[0] and norm[0] != "os_unknown":
                slug, _lbl = norm
                _upsert_observation(
                    conn,
                    asset_id,
                    "os_fingerprint_scan",
                    og,
                    slug,
                    sid_scan,
                    "",
                    "medium",
                    json.dumps({"field": "os_guess", "origin": "scanner_daemon"}, separators=(",", ":")),
                )
        cp = (cpe or "").strip()
        if cp:
            cn = _normalize_os_cpe(cp)
            if cn:
                slug, _lbl = cn
                _upsert_observation(
                    conn,
                    asset_id,
                    "os_fingerprint_cpe",
                    cp,
                    slug,
                    sid_scan,
                    "",
                    "high",
                    json.dumps({"field": "cpe", "origin": "scanner_daemon"}, separators=(",", ":")),
                )
        flat: list[str] = []
        if isinstance(discovery_sources, str):
            try:
                discovery_sources = json.loads(discovery_sources or "[]")
            except json.JSONDecodeError:
                discovery_sources = []
        if isinstance(discovery_sources, list):
            for d in discovery_sources:
                t = str(d).strip()
                if t:
                    flat.append(t)
        flat = sorted(set(flat))
        if flat:
            raw_ds = json.dumps(flat, separators=(",", ":"), ensure_ascii=False)
            _upsert_observation(
                conn,
                asset_id,
                "os_hint_enrichment",
                raw_ds,
                "",
                sid_enr,
                "",
                "low",
                json.dumps({"discovery_sources": flat, "origin": "scanner_daemon"}, separators=(",", ":"), ensure_ascii=False),
            )
    except (sqlite3.Error, TypeError, ValueError) as e:
        log.debug("recon observation write skipped: %s", e)


def _normalize_mac_identity(mac: str) -> str:
    m = (mac or "").strip().lower().replace("-", ":").replace(".", ":")
    return "".join(ch for ch in m if ch in "0123456789abcdef:")


def _identity_hostname_defs_from_string(
    raw: str, source_id: int, ref_prefix: str, prov_field: str, confidence: str = "medium"
) -> list[tuple[str, str, str, str, str, str]]:
    """Returns tuples (obs_type, raw, norm, source_ref, confidence, provenance_json)."""
    s = (raw or "").strip()
    if not s:
        return []
    low = s.lower().rstrip(".")
    if len(low) > 512:
        return []
    pfx = f"{ref_prefix}:" if ref_prefix else "h:"
    prov_base = json.dumps({"field": prov_field, "origin": "identity_scan"}, separators=(",", ":"))
    out: list[tuple[str, str, str, str, str, str]] = []
    if "." in low:
        short = low.split(".", 1)[0]
        if short and short != low:
            fqdn_prov = json.dumps(
                {"field": prov_field, "origin": "identity_scan"},
                separators=(",", ":"),
            )
            sh_prov = json.dumps(
                {"field": prov_field, "derived_from": "fqdn", "origin": "identity_scan"},
                separators=(",", ":"),
            )
            out.append(
                (
                    "fqdn_observed",
                    s,
                    low,
                    f"{pfx}fqdn",
                    confidence,
                    fqdn_prov,
                )
            )
            out.append(
                (
                    "hostname_observed",
                    s,
                    short,
                    f"{pfx}short",
                    confidence,
                    sh_prov,
                )
            )
        else:
            out.append(
                (
                    "hostname_observed",
                    s,
                    low,
                    f"{pfx}host",
                    confidence,
                    prov_base,
                )
            )
    else:
        out.append(
            (
                "hostname_observed",
                s,
                low,
                f"{pfx}host",
                confidence,
                prov_base,
            )
        )
    return out


def write_scan_identity_observations_best_effort(
    conn: sqlite3.Connection,
    asset_id: int,
    ip: str,
    mac: str,
    hostname: str,
    device_id: int,
) -> None:
    """Persist scan-side identity observations; never raises to callers."""
    if asset_id <= 0 or not _recon_tables_ready(conn):
        return
    try:
        _recon_seed_sources(conn)
        sid_scan = _recon_source_id(conn, "surveytrace_scan")
        if sid_scan is None:
            return
        ip_s = (ip or "").strip()
        if ip_s:
            try:
                import ipaddress

                if ipaddress.ip_address(ip_s).version == 4:
                    _upsert_observation(
                        conn,
                        asset_id,
                        "ipv4_observed",
                        ip_s,
                        ip_s.lower(),
                        sid_scan,
                        "asset_ip",
                        "medium",
                        json.dumps({"field": "ip", "origin": "scanner_daemon"}, separators=(",", ":")),
                    )
            except ValueError:
                pass
        mac_n = _normalize_mac_identity(mac)
        if mac_n:
            _upsert_observation(
                conn,
                asset_id,
                "mac_observed",
                (mac or "").strip(),
                mac_n,
                sid_scan,
                "asset_mac",
                "high",
                json.dumps({"field": "mac", "origin": "scanner_daemon"}, separators=(",", ":")),
            )
        if device_id and device_id > 0:
            ds = str(int(device_id))
            _upsert_observation(
                conn,
                asset_id,
                "device_link",
                ds,
                ds,
                sid_scan,
                f"device:{ds}",
                "high",
                json.dumps({"field": "device_id", "origin": "scanner_daemon"}, separators=(",", ":")),
            )
        hn = (hostname or "").strip()
        if hn:
            for ot, rv, nv, ref, conf, pj in _identity_hostname_defs_from_string(
                hn, sid_scan, "asset", "assets.hostname", "medium"
            ):
                _upsert_observation(conn, asset_id, ot, rv, nv, sid_scan, ref, conf, pj)
    except (sqlite3.Error, TypeError, ValueError) as e:
        log.debug("recon identity observation write skipped: %s", e)
