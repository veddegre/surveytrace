"""
SurveyTrace — SNMPv3 handshake for credential profile transport test (slice 5).

Single GET for sysDescr.0 (1.3.6.1.2.1.1.1.0) only. No walk, no SET.

Requires: pip install pysnmp (same as scanner / enrichment).
"""

from __future__ import annotations

import time
from typing import Any

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"


def run_test(payload: dict[str, Any]) -> dict[str, Any]:
    t0 = time.monotonic()
    transport = "snmpv3"
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
        return {
            "ok": False,
            "code": "dependency_missing",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
        }

    host = str(payload.get("target_host") or "").strip()
    port = int(payload.get("port") or 161)
    timeout = float(payload.get("timeout_sec") or 10.0)
    timeout = max(1.0, min(30.0, timeout))
    retries = 0
    principal = payload.get("principal") if isinstance(payload.get("principal"), dict) else {}
    secret = payload.get("secret") if isinstance(payload.get("secret"), dict) else {}

    user = str(
        principal.get("securityName")
        or principal.get("security_name")
        or principal.get("username")
        or ""
    ).strip()
    auth_pw = str(secret.get("auth_password") or "")
    priv_pw = str(secret.get("priv_password") or "")
    if not host or not user:
        return {
            "ok": False,
            "code": "invalid_profile",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
        }
    if not auth_pw and priv_pw:
        return {
            "ok": False,
            "code": "invalid_profile",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
        }
    if not auth_pw and not priv_pw:
        return {
            "ok": False,
            "code": "invalid_profile",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
        }

    ap = str(principal.get("authProtocol") or principal.get("auth_protocol") or "SHA").upper()
    pp = str(principal.get("privProtocol") or principal.get("priv_protocol") or "AES").upper()
    auth_proto = usmHMACSHAAuthProtocol if ap in ("SHA", "SHA1", "HMAC-SHA") else usmHMACMD5AuthProtocol
    if priv_pw:
        priv_proto = usmAesCfb128Protocol if pp in ("AES", "AES128", "AES-128") else usmDESPrivProtocol
        user_data = UsmUserData(
            user,
            authKey=auth_pw,
            privKey=priv_pw,
            authProtocol=auth_proto,
            privProtocol=priv_proto,
        )
    else:
        user_data = UsmUserData(
            user,
            authKey=auth_pw,
            authProtocol=auth_proto,
            privProtocol=usmNoPrivProtocol,
        )

    engine = SnmpEngine()
    try:
        target = UdpTransportTarget((host, port), timeout=timeout, retries=retries)
    except Exception:
        return {
            "ok": False,
            "code": "network_unreachable",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
        }

    ctx = ContextData()
    try:
        it = getCmd(
            engine,
            user_data,
            target,
            ctx,
            ObjectType(ObjectIdentity(OID_SYS_DESCR)),
        )
        error_indication, error_status, error_index, var_binds = next(it)
        if error_indication:
            msg = str(error_indication).lower()
            if "timeout" in msg or "timed out" in msg:
                code = "timeout"
            elif "network" in msg or "unreachable" in msg:
                code = "network_unreachable"
            elif "authentication" in msg or "auth" in msg:
                code = "auth_failed"
            else:
                code = "protocol_error"
            return {
                "ok": False,
                "code": code,
                "transport": transport,
                "duration_ms": int((time.monotonic() - t0) * 1000),
            }
        if error_status:
            return {
                "ok": False,
                "code": "auth_failed",
                "transport": transport,
                "duration_ms": int((time.monotonic() - t0) * 1000),
            }
        hint = ""
        if var_binds:
            try:
                hint = str(var_binds[0][1])[:128]
                hint = " ".join(hint.split())
            except Exception:
                hint = ""
        return {
            "ok": True,
            "code": "ok",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
            "hint": hint,
        }
    except Exception:
        return {
            "ok": False,
            "code": "protocol_error",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
        }
