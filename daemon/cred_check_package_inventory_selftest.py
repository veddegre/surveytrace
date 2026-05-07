#!/usr/bin/env python3
"""
No-network self-test: package inventory parse/sanitize caps.

Run from repo root:
  python3 daemon/cred_check_package_inventory_selftest.py
"""

from __future__ import annotations

import sys
from pathlib import Path

DAEMON = Path(__file__).resolve().parent
if str(DAEMON) not in sys.path:
    sys.path.insert(0, str(DAEMON))

from cred_check_ssh_packages import parse_tabular_package_lines


def _assert_len_cap(stored: list, max_rows_store: int, ctx: str) -> None:
    if len(stored) > max_rows_store:
        _fail(f"{ctx}: stored length {len(stored)} exceeds cap {max_rows_store}")


def _fail(msg: str) -> None:
    print("FAIL:", msg, file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    dpkg_sample = b"adduser\t3.137\tall\nzlib1g\t1:1.2.13.dfsg-1\tamd64\n"
    stored, total_ok, dropped, trunc = parse_tabular_package_lines(
        dpkg_sample,
        package_manager="dpkg",
        max_rows_store=5000,
        name_max=200,
        ver_max=200,
        arch_max=64,
    )
    if total_ok != 2 or dropped != 0 or trunc:
        _fail("dpkg sample counts")
    _assert_len_cap(stored, 5000, "dpkg sample")
    if stored[0]["name"] != "adduser":
        _fail("dpkg first name")

    rpm_sample = b"kernel\t5.14.0-503.el9.x86_64\tx86_64\nbash\t5.1.8-9.el9\tx86_64\n"
    s2, t2, d2, tr2 = parse_tabular_package_lines(
        rpm_sample,
        package_manager="rpm",
        max_rows_store=5000,
        name_max=200,
        ver_max=200,
        arch_max=64,
    )
    if t2 != 2 or d2 != 0 or tr2:
        _fail("rpm sample")
    if "5.14.0" not in s2[0]["version"]:
        _fail("rpm version field")
    _assert_len_cap(s2, 5000, "rpm sample")

    huge = b"a\t1\tall\n" * 50_000
    s3, t3, d3, tr3 = parse_tabular_package_lines(
        huge,
        package_manager="dpkg",
        max_rows_store=100,
        name_max=200,
        ver_max=200,
        arch_max=64,
    )
    if len(s3) != 100 or not tr3 or t3 != 50_000:
        _fail("row cap / truncation flag")
    _assert_len_cap(s3, 100, "huge rows")

    bad = b"only-two\tcols\nok\t1.0\tall\n"
    s4, t4, d4, tr4 = parse_tabular_package_lines(
        bad,
        package_manager="dpkg",
        max_rows_store=5000,
        name_max=200,
        ver_max=200,
        arch_max=64,
    )
    if t4 != 1 or d4 < 1:
        _fail("malformed line drop")
    _assert_len_cap(s4, 5000, "bad lines")

    long_name = "x" * 500
    long_line = f"{long_name}\t1.0\tall\n".encode()
    s5, t5, d5, tr5 = parse_tabular_package_lines(
        long_line,
        package_manager="dpkg",
        max_rows_store=10,
        name_max=80,
        ver_max=80,
        arch_max=16,
    )
    if not s5 or len(s5[0]["name"]) > 80 or len(s5[0]["version"]) > 80:
        _fail("field length cap")
    _assert_len_cap(s5, 10, "long fields")

    sec = b"BEGIN PRIVATE KEY\t1\tall\nokpkg\t1\tall\n"
    s6, t6, d6, tr6 = parse_tabular_package_lines(
        sec,
        package_manager="dpkg",
        max_rows_store=50,
        name_max=200,
        ver_max=200,
        arch_max=64,
    )
    if t6 != 1 or d6 < 1:
        _fail("sensitive name dropped")
    joined = "\t".join(s6[0].values())
    if "PRIVATE" in joined or "BEGIN" in joined:
        _fail("secret leakage in stored row")
    _assert_len_cap(s6, 50, "sensitive")

    s7, t7, d7, tr7 = parse_tabular_package_lines(
        b"",
        package_manager="dpkg",
        max_rows_store=100,
        name_max=200,
        ver_max=200,
        arch_max=64,
    )
    if s7 or t7 != 0 or tr7:
        _fail("empty output parse")
    _assert_len_cap(s7, 100, "empty")

    flood = b"z\t9\tall\n" * 20
    sf, tf, df, trf = parse_tabular_package_lines(
        flood,
        package_manager="dpkg",
        max_rows_store=5000,
        name_max=200,
        ver_max=200,
        arch_max=64,
        max_lines_scan=5,
    )
    if tf != 5 or not trf:
        _fail("max_lines_scan should cap count and set truncated")
    _assert_len_cap(sf, 5000, "line scan")

    trunc_body = b"x\t1\tall\n" * 300
    s8, t8, d8, tr8 = parse_tabular_package_lines(
        trunc_body,
        package_manager="dpkg",
        max_rows_store=50,
        name_max=10,
        ver_max=10,
        arch_max=10,
    )
    if len(s8) != 50 or not tr8 or t8 != 300:
        _fail("storage truncation vs total")
    _assert_len_cap(s8, 50, "trunc_body")

    print("OK cred_check_package_inventory_selftest")


if __name__ == "__main__":
    main()
