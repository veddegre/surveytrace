"""
Bounded SSH package inventory for ssh.linux.package_inventory@1.0.0 (slice 8).

Fixed commands only (no operator argv, no PTY):
  dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\n'
  rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n'

Tries dpkg first; on failure / empty / missing, tries rpm. Same SSH connect + host-key policy as cred_check_ssh_os_release.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

log = logging.getLogger(__name__)

from cred_check_ssh_os_release import _connect_client, read_exec_stdout_bounded

# Fixed remote command strings (shell on server may wrap; strings are literal allowlisted).
DPKG_QUERY_CMD = "dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\n'"
RPM_QA_CMD = "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n'"

_PKG_NAME_SUSPICIOUS = re.compile(r"(?i)(^[\s]*$|BEGIN |PRIVATE KEY|password\s*=|secret\s*=)")
_FIELD_SAFE = re.compile(r"[^\x20-\x7E]+")

# Prevent adversarial tiny-line flooding after stdout cap (~6 MiB could yield millions of lines).
_MAX_LINES_SCAN_DEFAULT = 500_000


def _iter_lines_bytes(data: bytes):
    """Single-pass newline splitting without ``bytes.splitlines()`` materializing all lines."""
    start = 0
    n = len(data)
    while start < n:
        idx = data.find(b"\n", start)
        if idx == -1:
            yield data[start:n]
            return
        yield data[start:idx]
        start = idx + 1


def _sanitize_field(s: str, mx: int) -> str:
    t = _FIELD_SAFE.sub("", (s or "").strip())[:mx]
    return t


def parse_tabular_package_lines(
    raw: bytes,
    *,
    package_manager: str,
    max_rows_store: int,
    name_max: int,
    ver_max: int,
    arch_max: int,
    max_lines_scan: int | None = None,
) -> tuple[list[dict[str, str]], int, int, bool]:
    """
    Parse tab-separated name, version, arch lines.
    Returns (stored_packages, total_valid_lines, dropped_malformed, truncated_storage).

    Stores at most ``max_rows_store`` dicts (bounded RAM); counts valid rows until
    ``max_lines_scan`` physical lines, then stops with truncated_storage set.
    """
    _ = package_manager  # reserved for future format variants
    if max_lines_scan is None:
        cap_lines = min(2_000_000, _MAX_LINES_SCAN_DEFAULT)
    else:
        cap_lines = max(1, min(2_000_000, int(max_lines_scan)))
    stored: list[dict[str, str]] = []
    dropped = 0
    total_ok = 0
    truncated_scan = False
    lines_seen = 0
    for line_bytes in _iter_lines_bytes(raw):
        lines_seen += 1
        if lines_seen > cap_lines:
            truncated_scan = True
            break
        try:
            line = line_bytes.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError:
            line = line_bytes.decode("utf-8", errors="replace").strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            dropped += 1
            continue
        name = _sanitize_field(parts[0], name_max)
        ver = _sanitize_field(parts[1], ver_max)
        arch = _sanitize_field(parts[2], arch_max)
        if not name or _PKG_NAME_SUSPICIOUS.search(name):
            dropped += 1
            continue
        total_ok += 1
        if len(stored) < max_rows_store:
            stored.append({"name": name, "version": ver, "arch": arch})
    truncated_storage = truncated_scan or total_ok > max_rows_store
    return stored, total_ok, dropped, truncated_storage


def collect_package_inventory(
    *,
    host: str,
    port: int,
    principal: dict[str, Any],
    secret: dict[str, Any],
    timeout_sec: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> dict[str, Any]:
    """
    Returns ok, code, package_manager, stdout_raw, duration_ms, stderr_snippet_len, exit_code,
    detector (dpkg|rpm|none), truncated_read (stdout cap hit before parse).
    """
    t0 = time.monotonic()
    out: dict[str, Any] = {
        "ok": False,
        "code": "unsupported_os",
        "package_manager": "unknown",
        "stdout_raw": None,
        "duration_ms": 0,
        "stderr_snippet_len": 0,
        "exit_code": None,
        "detector": "none",
        "truncated_read": False,
    }
    try:
        import paramiko  # noqa: F401
    except ImportError:
        out["code"] = "dependency_missing"
        out["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return out

    host = (host or "").strip()
    username = str(principal.get("username") or "").strip()
    if not host or not username:
        out["code"] = "invalid_profile"
        out["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return out

    password = str(secret.get("password") or "")
    pem = str(secret.get("private_key") or "")
    passphrase = str(secret.get("passphrase") or "") or None
    port = int(port or 22)
    timeout_sec = float(max(3.0, min(300.0, timeout_sec)))
    max_stdout_bytes = int(max(4096, min(6_291_456, max_stdout_bytes)))
    max_stderr_bytes = int(max(256, min(65_536, max_stderr_bytes)))

    client, err, connect_detail = _connect_client(
        host=host,
        port=port,
        username=username,
        password=password,
        pem=pem,
        passphrase=passphrase,
        timeout_sec=timeout_sec,
    )
    if client is None:
        out["code"] = err or "protocol_error"
        if connect_detail:
            out["connect_detail_safe"] = connect_detail
        out["duration_ms"] = int((time.monotonic() - t0) * 1000)
        log.warning(
            "cred_check ssh package_inventory: connect failed host=%s port=%s user=%s code=%s detail=%s",
            host,
            port,
            username,
            out["code"],
            connect_detail or "",
        )
        return out

    def try_cmd(cmd: str) -> tuple[bytes | None, int | None, str | None, int, bool]:
        raw_o, err_raw, rc, ex, stdout_trunc = read_exec_stdout_bounded(
            client,
            command=cmd,
            timeout_sec=timeout_sec,
            max_bytes=max_stdout_bytes,
            max_stderr=max_stderr_bytes,
            overflow_mode="truncate",
        )
        slen = len(err_raw or b"")
        return raw_o, rc, ex, slen, stdout_trunc

    try:
        raw_d, rc_d, ex_d, slen_d, trunc_d = try_cmd(DPKG_QUERY_CMD)
        out["stderr_snippet_len"] = slen_d
        if ex_d:
            out["code"] = ex_d
            out["duration_ms"] = int((time.monotonic() - t0) * 1000)
            return out
        if raw_d is not None and rc_d == 0:
            out["ok"] = True
            out["code"] = "ok"
            out["package_manager"] = "dpkg"
            out["stdout_raw"] = raw_d
            out["exit_code"] = rc_d
            out["detector"] = "dpkg"
            out["truncated_read"] = bool(trunc_d)
            out["duration_ms"] = int((time.monotonic() - t0) * 1000)
            return out

        raw_r, rc_r, ex_r, slen_r, trunc_r = try_cmd(RPM_QA_CMD)
        out["stderr_snippet_len"] = max(out["stderr_snippet_len"], slen_r)
        if ex_r:
            out["code"] = ex_r
            out["duration_ms"] = int((time.monotonic() - t0) * 1000)
            return out
        if raw_r is not None and rc_r == 0:
            out["ok"] = True
            out["code"] = "ok"
            out["package_manager"] = "rpm"
            out["stdout_raw"] = raw_r
            out["exit_code"] = rc_r
            out["detector"] = "rpm"
            out["truncated_read"] = bool(trunc_r)
            out["duration_ms"] = int((time.monotonic() - t0) * 1000)
            return out

        out["code"] = "unsupported_os"
        out["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return out
    finally:
        try:
            client.close()
        except Exception:
            pass
