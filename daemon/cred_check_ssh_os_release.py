"""
Bounded SSH read of /etc/os-release for ssh.linux.os_release@1.0.0 (slice 7).

- Fixed remote path only (/etc/os-release) via SFTP, else allowlisted `cat /etc/os-release` exec.
- No PTY, no operator argv, no shell interpolation of user data.
- Mirrors host-key policy from cred_transport_ssh (SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY).
"""

from __future__ import annotations

import io
import logging
import os
import socket
import time
from typing import Any

log = logging.getLogger(__name__)

# Allowlisted remote read (must match plugin manifest).
REMOTE_PATH = "/etc/os-release"
# Fixed argv only — no user strings concatenated into remote shell.
EXEC_FALLBACK_ARGV = "cat /etc/os-release"


def _policy_from_env():
    import paramiko

    raw = (os.environ.get("SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY") or "").strip().lower()
    if raw in ("reject", "strict", "no"):
        return paramiko.RejectPolicy()
    return paramiko.AutoAddPolicy()


def _connect_client(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    pem: str,
    passphrase: str | None,
    timeout_sec: float,
):
    import paramiko

    pkey = None
    if pem:
        last_err = None
        for cls in (
            getattr(paramiko, "RSAKey", None),
            getattr(paramiko, "Ed25519Key", None),
            getattr(paramiko, "ECDSAKey", None),
        ):
            if cls is None:
                continue
            try:
                pkey = cls.from_private_key(io.StringIO(pem), password=passphrase or None)
                break
            except Exception as e:
                last_err = e
                pkey = None
        if pkey is None:
            return None, "auth_failed"
    if not password and pkey is None:
        return None, "auth_failed"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(_policy_from_env())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password or None,
            pkey=pkey,
            timeout=timeout_sec,
            banner_timeout=timeout_sec,
            auth_timeout=timeout_sec,
            allow_agent=False,
            look_for_keys=False,
        )
        return client, None
    except paramiko.AuthenticationException:
        return None, "auth_failed"
    except paramiko.BadHostKeyException:
        return None, "host_key_mismatch"
    except paramiko.SSHException:
        return None, "protocol_error"
    except socket.timeout:
        return None, "timeout"
    except OSError:
        return None, "network_unreachable"
    except Exception:
        return None, "protocol_error"


def _read_sftp_max(client: Any, *, max_bytes: int) -> tuple[bytes | None, str | None]:
    try:
        sftp = client.open_sftp()
        try:
            with sftp.open(REMOTE_PATH, "r") as rf:  # type: ignore[attr-defined]
                chunks: list[bytes] = []
                total = 0
                while total <= max_bytes:
                    piece = rf.read(min(8192, max_bytes + 1 - total))
                    if not piece:
                        break
                    chunks.append(piece)
                    total += len(piece)
                raw = b"".join(chunks)
                if len(raw) > max_bytes:
                    return None, "output_too_large"
                return raw, None
        finally:
            try:
                sftp.close()
            except Exception:
                pass
    except Exception as e:
        log.debug("sftp read failed: %s", e)
        return None, "sftp_unavailable"


def read_exec_stdout_bounded(
    client: Any,
    *,
    command: str,
    timeout_sec: float,
    max_bytes: int,
    max_stderr: int,
    overflow_mode: str = "fail",
) -> tuple[bytes | None, bytes, int | None, str | None, bool]:
    """
    Single fixed remote command string, no PTY. Captures stdout up to max_bytes (+1 detects overflow).

    overflow_mode:
      - "fail": if stdout exceeds max_bytes, returns (None, ..., "output_too_large", False).
      - "truncate": stdout is clipped to max_bytes and the last bool is True when clipped.

    Returns (stdout_or_none, stderr_raw_capped, exit_code, error_code, stdout_truncated).
    """
    import paramiko

    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout_sec, get_pty=False)
        try:
            stdin.close()
        except Exception:
            pass
        out_chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            piece = stdout.channel.recv(min(16384, max_bytes + 1 - total))
            if not piece:
                break
            out_chunks.append(piece)
            total += len(piece)
        raw_out = b"".join(out_chunks)
        err_raw = (stderr.read(max_stderr + 1) or b"")[:max_stderr]
        rc = stdout.channel.recv_exit_status()
        stdout_truncated = False
        if len(raw_out) > max_bytes:
            if overflow_mode == "truncate":
                raw_out = raw_out[:max_bytes]
                stdout_truncated = True
            else:
                return None, err_raw, rc, "output_too_large", False
        return raw_out, err_raw, rc, None, stdout_truncated
    except socket.timeout:
        return None, b"", None, "timeout", False
    except paramiko.SSHException:
        return None, b"", None, "protocol_error", False
    except Exception:
        return None, b"", None, "command_failed", False


def _read_exec_max(client: Any, *, timeout_sec: float, max_bytes: int, max_stderr: int) -> tuple[bytes | None, bytes, int | None, str | None]:
    raw_o, err_raw, rc, ex, _trunc = read_exec_stdout_bounded(
        client,
        command=EXEC_FALLBACK_ARGV,
        timeout_sec=timeout_sec,
        max_bytes=max_bytes,
        max_stderr=max_stderr,
        overflow_mode="fail",
    )
    return raw_o, err_raw, rc, ex


def collect_os_release(
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
    Returns dict with keys: ok (bool), code (str), duration_ms, stdout (bytes|None),
    stderr_snippet (str), exit_code (int|None), truncated (bool).
    """
    t0 = time.monotonic()
    out: dict[str, Any] = {
        "ok": False,
        "code": "protocol_error",
        "duration_ms": 0,
        "stdout": None,
        "stderr_snippet": "",
        "exit_code": None,
        "truncated": False,
    }
    try:
        import paramiko  # noqa: F401
    except ImportError:
        out["code"] = "protocol_error"
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
    timeout_sec = float(max(3.0, min(120.0, timeout_sec)))
    max_stdout_bytes = int(max(1024, min(2_097_152, max_stdout_bytes)))
    max_stderr_bytes = int(max(256, min(65_536, max_stderr_bytes)))

    client, err = _connect_client(
        host=host,
        port=port,
        username=username,
        password=password,
        pem=pem,
        passphrase=passphrase,
        timeout_sec=timeout_sec,
    )
    out["duration_ms"] = int((time.monotonic() - t0) * 1000)
    if client is None:
        out["code"] = err or "protocol_error"
        return out

    try:
        raw, sftp_err = _read_sftp_max(client, max_bytes=max_stdout_bytes)
        if raw is not None:
            out["ok"] = True
            out["code"] = "ok"
            out["stdout"] = raw
            out["duration_ms"] = int((time.monotonic() - t0) * 1000)
            return out

        raw2, err_raw, rc, ex_err = _read_exec_max(
            client, timeout_sec=timeout_sec, max_bytes=max_stdout_bytes, max_stderr=max_stderr_bytes
        )
        out["exit_code"] = rc
        out["stderr_snippet"] = err_raw.decode("utf-8", errors="replace")[:512]
        if ex_err:
            out["code"] = ex_err
            out["duration_ms"] = int((time.monotonic() - t0) * 1000)
            return out
        if rc not in (0, None):
            out["code"] = "command_failed"
            out["duration_ms"] = int((time.monotonic() - t0) * 1000)
            return out
        out["ok"] = True
        out["code"] = "ok"
        out["stdout"] = raw2 or b""
        out["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return out
    finally:
        try:
            client.close()
        except Exception:
            pass
