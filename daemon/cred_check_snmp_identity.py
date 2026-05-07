"""
SNMPv3 device identity for snmpv3.device_identity@1.0.0 (slice 9).

Fixed GET allowlist only — sysDescr.0, sysObjectID.0, sysName.0.
No walk, no SET, no operator OIDs.
"""

from __future__ import annotations

import re
import time
from typing import Any

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

SYS_DESCR_MAX = 2048
SYS_OBJECT_ID_MAX = 256
SYS_NAME_MAX = 256

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_snmp_display_string(s: str | None, mx: int) -> str:
    if s is None:
        return ""
    t = _CTRL.sub("", str(s)).strip()
    if len(t) > mx:
        t = t[:mx]
    return t


def _normalize_auth_kind(auth_protocol: str) -> str | None:
    s = auth_protocol.strip().upper().replace("-", "").replace("_", "")
    if s in ("SHA", "SHA1", "HMACSHA"):
        return "sha"
    if s in ("MD5", "HMACMD5"):
        return "md5"
    return None


def _normalize_priv_kind(priv_protocol: str) -> str | None:
    s = priv_protocol.strip().upper().replace("-", "").replace("_", "")
    if s in ("AES", "AES128"):
        return "aes"
    if s == "DES":
        return "des"
    return None


def validate_snmpv3_profile(principal: dict[str, Any], secret: dict[str, Any]) -> str | None:
    """
    Returns error_code string if invalid, else None.
    """
    user = str(
        principal.get("securityName")
        or principal.get("security_name")
        or principal.get("username")
        or ""
    ).strip()
    if not user:
        return "invalid_profile"

    auth_pw = str(secret.get("auth_password") or "")
    priv_pw = str(secret.get("priv_password") or "")
    if priv_pw and not auth_pw:
        return "invalid_profile"
    if not auth_pw and not priv_pw:
        return "invalid_profile"

    ap_raw = str(principal.get("authProtocol") or principal.get("auth_protocol") or "SHA")
    pp_raw = str(principal.get("privProtocol") or principal.get("priv_protocol") or "AES")
    if _normalize_auth_kind(ap_raw) is None:
        return "invalid_profile"
    if priv_pw and _normalize_priv_kind(pp_raw) is None:
        return "invalid_profile"

    sl = str(principal.get("securityLevel") or principal.get("security_level") or "").strip().upper().replace(" ", "")
    if sl in ("NOAUTHNOPRIV", "NOAUTH_NOPRIV"):
        return "invalid_profile"
    if sl in ("AUTHPRIV", "AUTH_PRIV") and not priv_pw:
        return "invalid_profile"
    if sl in ("AUTHNOPRIV", "AUTH_NOPRIV") and priv_pw:
        return "invalid_profile"

    return None


def extract_vendor_hint(sys_object_id: str) -> str:
    o = (sys_object_id or "").strip()
    parts = o.replace("OID:", "").strip().split(".")
    nums: list[str] = []
    for p in parts:
        p = p.strip()
        if p.isdigit():
            nums.append(p)
    # 1.3.6.1.4.1.{enterprise}.…
    try:
        if len(nums) >= 7 and nums[:6] == ["1", "3", "6", "1", "4", "1"]:
            return f"ent:{nums[6]}"
    except IndexError:
        pass
    return "unknown"


def build_normalized_identity(sys_descr: str, sys_object_id: str, sys_name: str) -> dict[str, str]:
    vendor = extract_vendor_hint(sys_object_id)
    name_guess = sanitize_snmp_display_string(sys_name, SYS_NAME_MAX) or ""
    if not name_guess and sys_descr:
        first = sys_descr.strip().split(None, 1)
        name_guess = sanitize_snmp_display_string(first[0] if first else "", 64) or ""
    model_hint = ""
    if sys_descr:
        model_hint = sanitize_snmp_display_string(sys_descr, 120)
    return {
        "name": name_guess or "unknown",
        "vendor_hint": vendor,
        "model_hint": model_hint or "unknown",
    }


def _oid_kind(oid_str: str) -> str | None:
    s = oid_str.strip()
    if OID_SYS_DESCR in s or s.endswith("1.1.1.0") or s.endswith("sysDescr.0"):
        return "descr"
    if OID_SYS_OBJECT_ID in s or s.endswith("1.1.2.0") or s.endswith("sysObjectID.0"):
        return "obj"
    if OID_SYS_NAME in s or s.endswith("1.1.5.0") or s.endswith("sysName.0"):
        return "name"
    return None


def parse_snmp_varbinds(var_binds: Any) -> tuple[str | None, str | None, str | None]:
    """Map GET response varbinds to sanitized strings (no network)."""
    descr_o: str | None = None
    obj_o: str | None = None
    name_o: str | None = None
    if not var_binds:
        return None, None, None

    for vb in var_binds:
        try:
            oid, val = vb[0], vb[1]
            oid_str = oid.prettyPrint() if hasattr(oid, "prettyPrint") else str(oid)
            vs = val.prettyPrint() if hasattr(val, "prettyPrint") else str(val)
        except Exception:
            continue
        low = vs.lower()
        if "no such object" in low or "no such instance" in low:
            v_clean = None
        else:
            v_clean = vs.strip() if vs and str(vs).strip() else None

        kind = _oid_kind(oid_str)
        if kind == "descr":
            descr_o = v_clean
        elif kind == "obj":
            obj_o = v_clean
        elif kind == "name":
            name_o = v_clean

    sd = sanitize_snmp_display_string(descr_o, SYS_DESCR_MAX) if descr_o else ""
    so = sanitize_snmp_display_string(obj_o, SYS_OBJECT_ID_MAX) if obj_o else ""
    sn = sanitize_snmp_display_string(name_o, SYS_NAME_MAX) if name_o else ""
    return (
        sd if sd else None,
        so if so else None,
        sn if sn else None,
    )


def classify_identity_partial(descr: str | None, obj: str | None, name: str | None) -> tuple[str, bool]:
    """Returns (status success|partial|failed, partial_flag for normalized_json)."""
    n = sum(1 for x in (descr, obj, name) if x)
    if n == 3:
        return "success", False
    if n > 0:
        return "partial", True
    return "failed", True


def collect_snmp_device_identity(
    *,
    host: str,
    port: int,
    principal: dict[str, Any],
    secret: dict[str, Any],
    timeout_sec: float,
) -> dict[str, Any]:
    t0 = time.monotonic()
    out: dict[str, Any] = {
        "ok": False,
        "code": "protocol_error",
        "duration_ms": 0,
        "sys_descr": None,
        "sys_object_id": None,
        "sys_name": None,
    }
    err = validate_snmpv3_profile(principal, secret)
    if err:
        out["code"] = err
        out["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return out

    try:
        from pysnmp.hlapi import (
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            UsmUserData,
            getCmd,
            usmAesCfb128Protocol,
            usmDESPrivProtocol,
            usmHMACMD5AuthProtocol,
            usmHMACSHAAuthProtocol,
            usmNoPrivProtocol,
        )
    except ImportError:
        out["code"] = "dependency_missing"
        out["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return out

    host = (host or "").strip()
    if not host:
        out["code"] = "invalid_profile"
        out["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return out

    port = int(port or 161)
    if not (1 <= port <= 65535):
        port = 161

    timeout_sec = float(max(1.0, min(120.0, timeout_sec)))

    user = str(
        principal.get("securityName")
        or principal.get("security_name")
        or principal.get("username")
        or ""
    ).strip()
    auth_pw = str(secret.get("auth_password") or "")
    priv_pw = str(secret.get("priv_password") or "")

    ap_raw = str(principal.get("authProtocol") or principal.get("auth_protocol") or "SHA")
    pp_raw = str(principal.get("privProtocol") or principal.get("priv_protocol") or "AES")
    auth_kind = _normalize_auth_kind(ap_raw)
    priv_kind = _normalize_priv_kind(pp_raw)
    auth_proto = usmHMACSHAAuthProtocol if auth_kind == "sha" else usmHMACMD5AuthProtocol
    if priv_pw:
        priv_proto = usmAesCfb128Protocol if priv_kind == "aes" else usmDESPrivProtocol
        user_data = UsmUserData(user, authKey=auth_pw, privKey=priv_pw, authProtocol=auth_proto, privProtocol=priv_proto)
    else:
        user_data = UsmUserData(user, authKey=auth_pw, authProtocol=auth_proto, privProtocol=usmNoPrivProtocol)

    engine = SnmpEngine()
    try:
        target = UdpTransportTarget((host, port), timeout=timeout_sec, retries=0)
    except Exception:
        out["code"] = "network_unreachable"
        out["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return out

    ctx = ContextData()
    try:
        it = getCmd(
            engine,
            user_data,
            target,
            ctx,
            ObjectType(ObjectIdentity(OID_SYS_DESCR)),
            ObjectType(ObjectIdentity(OID_SYS_OBJECT_ID)),
            ObjectType(ObjectIdentity(OID_SYS_NAME)),
        )
        error_indication, error_status, error_index, var_binds = next(it)
        if error_indication:
            msg = str(error_indication).lower()
            if "timeout" in msg or "timed out" in msg:
                code = "timeout"
            elif "network" in msg or "unreachable" in msg:
                code = "network_unreachable"
            elif "authentication" in msg or "auth" in msg or "cipher" in msg or "digest" in msg:
                code = "auth_failed"
            else:
                code = "protocol_error"
            out["code"] = code
            out["duration_ms"] = int((time.monotonic() - t0) * 1000)
            return out
        if error_status:
            out["code"] = "auth_failed"
            out["duration_ms"] = int((time.monotonic() - t0) * 1000)
            return out

        sd, so, sn = parse_snmp_varbinds(var_binds)
        out["sys_descr"] = sd
        out["sys_object_id"] = so
        out["sys_name"] = sn
        out["ok"] = True
        out["code"] = "ok"
        out["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return out
    except Exception:
        out["code"] = "protocol_error"
        out["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return out
