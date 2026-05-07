#!/usr/bin/env python3
"""
No-network self-test: os-release parse, sanitization caps, normalizer (slice 7).

Run from repo root:
  python3 daemon/cred_check_slice7_selftest.py
"""

from __future__ import annotations

import sys
from pathlib import Path

DAEMON = Path(__file__).resolve().parent
if str(DAEMON) not in sys.path:
    sys.path.insert(0, str(DAEMON))

import recon_observations as recon
from cred_check_run import (
    _os_release_display,
    _parse_os_release_text,
    _sanitize_os_release_for_result,
)


def _fail(msg: str) -> None:
    print("FAIL:", msg, file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    sample = b'NAME="Ubuntu"\nVERSION_ID="22.04"\nPRETTY_NAME=Ubuntu 22.04.5 LTS\nID=ubuntu\n'
    kv, err = _parse_os_release_text(sample)
    if err is not None or kv is None:
        _fail("parse ubuntu sample")
    if kv.get("ID") != "ubuntu":
        _fail("ID field")
    disp = _os_release_display(kv)
    if "Ubuntu" not in disp and "22.04" not in disp:
        _fail("display string")
    slug, _lbl = recon.normalize_os_text_public(disp)
    if "ubuntu" not in slug:
        _fail("normalizer slug " + repr(slug))

    huge_val = b"FOO=" + (b"x" * 50_000) + b"\nID=debian\nVERSION_ID=12\n"
    kv2, err2 = _parse_os_release_text(huge_val)
    if err2 is not None or kv2 is None:
        _fail("parse huge value line")
    safe = _sanitize_os_release_for_result(kv2)
    if len(safe) > 64:
        _fail("sanitize key cap")
    if any(len(v) > 1024 for v in safe.values()):
        _fail("sanitize val cap")

    sec = _sanitize_os_release_for_result(
        {"ID": "linux", "PASSWORD": "nope", "APIKEY": "nope", "MY_SECRET": "x", "OK": "1"}
    )
    if any(k.upper() in ("PASSWORD", "APIKEY", "MY_SECRET") for k in sec.keys()):
        _fail("sensitive key leaked: " + repr(list(sec.keys())))
    if sec.get("OK") != "1" or sec.get("ID") != "linux":
        _fail("expected OK and ID retained")

    empty, e3 = _parse_os_release_text(b"# only\n\n")
    if empty is not None:
        _fail("expected empty parse failure")
    if e3 != "normalize_error":
        _fail("empty parse error code")

    print("OK cred_check_slice7_selftest")


if __name__ == "__main__":
    main()
