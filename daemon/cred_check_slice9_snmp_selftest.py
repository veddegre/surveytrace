#!/usr/bin/env python3
"""
No-network self-test: SNMPv3 device identity validation + parse helpers (slice 9).

Run from repo root:
  python3 daemon/cred_check_slice9_snmp_selftest.py
"""

from __future__ import annotations

import sys
from pathlib import Path

DAEMON = Path(__file__).resolve().parent
if str(DAEMON) not in sys.path:
    sys.path.insert(0, str(DAEMON))

from cred_check_snmp_identity import (
    build_normalized_identity,
    classify_identity_partial,
    extract_vendor_hint,
    parse_snmp_varbinds,
    sanitize_snmp_display_string,
    validate_snmpv3_profile,
)


class _PP:
    def __init__(self, s: str) -> None:
        self._s = s

    def prettyPrint(self) -> str:
        return self._s


def _fail(msg: str) -> None:
    print("FAIL:", msg, file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    p_ok = {"securityName": "u", "auth_protocol": "SHA", "priv_protocol": "AES"}
    s_ok = {"auth_password": "x", "priv_password": "y"}
    if validate_snmpv3_profile(p_ok, s_ok) is not None:
        _fail("valid authPriv")

    if validate_snmpv3_profile({"securityName": "", "auth_protocol": "SHA"}, {"auth_password": "a"}) != "invalid_profile":
        _fail("missing user")

    if validate_snmpv3_profile({"securityName": "u"}, {"priv_password": "p"}) != "invalid_profile":
        _fail("priv without auth")

    if validate_snmpv3_profile({"securityName": "u"}, {}) != "invalid_profile":
        _fail("empty secret")

    if validate_snmpv3_profile({"securityName": "u", "auth_protocol": "BLAH"}, {"auth_password": "a"}) != "invalid_profile":
        _fail("bad auth proto")

    if validate_snmpv3_profile({"securityName": "u", "auth_protocol": "SHA", "priv_protocol": "WEP"}, {"auth_password": "a", "priv_password": "b"}) != "invalid_profile":
        _fail("bad priv proto")

    if validate_snmpv3_profile({"securityName": "u", "security_level": "authPriv"}, {"auth_password": "a"}) != "invalid_profile":
        _fail("authPriv without priv_pw")

    if validate_snmpv3_profile({"securityName": "u", "security_level": "authNoPriv"}, {"auth_password": "a", "priv_password": "b"}) != "invalid_profile":
        _fail("authNoPriv with priv_pw")

    if validate_snmpv3_profile({"securityName": "u", "security_level": "noAuthNoPriv"}, {"auth_password": "a"}) != "invalid_profile":
        _fail("noAuthNoPriv rejected")

    bad_char = "abc\x01def"
    sx = sanitize_snmp_display_string(bad_char, 100)
    if "\x01" in sx:
        _fail("control strip")

    long_s = "z" * 5000
    if len(sanitize_snmp_display_string(long_s, 200)) != 200:
        _fail("length cap")

    vb = [
        (_PP("1.3.6.1.2.1.1.1.0"), _PP("Cisco IOS Software")),
        (_PP("1.3.6.1.2.1.1.2.0"), _PP("1.3.6.1.4.1.9.1.999")),
        (_PP("1.3.6.1.2.1.1.5.0"), _PP("switch01.example.com")),
    ]
    d, o, n = parse_snmp_varbinds(vb)
    if not d or "Cisco" not in d or not o or not n:
        _fail("parse three OIDs")

    vb2 = [
        (_PP("SNMPv2-MIB::sysDescr.0"), _PP("Linux foo")),
        (_PP("SNMPv2-MIB::sysObjectID.0"), _PP("NET-SNMP-MIB::netSnmpAgentOIDs.10")),
        (_PP("SNMPv2-MIB::sysName.0"), _PP("No Such Instance currently exists at this OID")),
    ]
    d2, o2, n2 = parse_snmp_varbinds(vb2)
    if d2 != "Linux foo" or n2 is not None:
        _fail("noSuchInstance drop")

    vb3 = [
        (_PP("1.3.6.1.2.1.1.1.0"), _PP("Short")),
        (_PP("1.3.6.1.2.1.1.2.0"), _PP("No Such Object currently exists at this OID")),
        (_PP("1.3.6.1.2.1.1.5.0"), _PP("host")),
    ]
    d3, o3, n3 = parse_snmp_varbinds(vb3)
    st, pf = classify_identity_partial(d3, o3, n3)
    if st != "partial" or not pf:
        _fail("missing one OID → partial")

    st4, pf4 = classify_identity_partial(None, None, None)
    if st4 != "failed":
        _fail("all missing → failed")

    if extract_vendor_hint("1.3.6.1.4.1.9.1.1") != "ent:9":
        _fail("vendor hint")

    ni = build_normalized_identity("One Two Three", "1.3.6.1.4.1.12345.1", "my.host")
    if ni.get("name") != "my.host":
        _fail("normalized name prefers sysName")

    print("OK cred_check_slice9_snmp_selftest")


if __name__ == "__main__":
    main()
