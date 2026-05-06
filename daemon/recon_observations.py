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
