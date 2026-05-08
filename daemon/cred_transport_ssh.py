"""
SurveyTrace — SSH handshake for credential profile transport test (slice 5).

Handshake only: TCP + SSH auth + exec fixed allowlisted command `true`.
No plugin execution, no shell session, no operator-supplied remote command.

Requires: pip install paramiko
Host key policy: UI handshake sets SURVEYTRACE_CRED_TRANSPORT_HANDSHAKE=1 (AutoAddPolicy).
Production cred SSH checks use SURVEYTRACE_CRED_SSH_CHECK_HOST_KEY_POLICY (preferred) or
SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY in cred_check_ssh_os_release.py.
"""

from __future__ import annotations

import io
import os
import socket
import time
from typing import Any


def _policy_from_env():
    import paramiko

    # API handshake subprocess only — ignore pool-wide reject/strict for first-connect tests.
    raw_hand = (os.environ.get("SURVEYTRACE_CRED_TRANSPORT_HANDSHAKE") or "").strip().lower()
    if raw_hand in ("1", "true", "yes", "on"):
        return paramiko.AutoAddPolicy()

    raw = (os.environ.get("SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY") or "").strip().lower()
    if raw in ("reject", "strict", "no"):
        return paramiko.RejectPolicy()
    # default accept_new for operator handshake tests (MITM risk — document in ops docs)
    return paramiko.AutoAddPolicy()


def run_test(payload: dict[str, Any]) -> dict[str, Any]:
    t0 = time.monotonic()
    transport = "ssh"
    try:
        import paramiko
    except ImportError:
        return {
            "ok": False,
            "code": "dependency_missing",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
        }

    host = str(payload.get("target_host") or "").strip()
    port = int(payload.get("port") or 22)
    timeout = float(payload.get("timeout_sec") or 15.0)
    timeout = max(3.0, min(30.0, timeout))
    principal = payload.get("principal") if isinstance(payload.get("principal"), dict) else {}
    secret = payload.get("secret") if isinstance(payload.get("secret"), dict) else {}
    username = str(principal.get("username") or "").strip()
    if not host or not username:
        return {
            "ok": False,
            "code": "invalid_profile",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
        }

    password = str(secret.get("password") or "")
    pem = str(secret.get("private_key") or "")
    passphrase = str(secret.get("passphrase") or "") or None
    if not password and not pem:
        return {
            "ok": False,
            "code": "invalid_profile",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
        }

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
                pkey = cls.from_private_key(io.StringIO(pem), password=passphrase)
                break
            except Exception as e:
                last_err = e
                pkey = None
        if pkey is None:
            return {
                "ok": False,
                "code": "auth_failed",
                "transport": transport,
                "duration_ms": int((time.monotonic() - t0) * 1000),
            }

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(_policy_from_env())
    try:
        client.connect(
            host,
            port=port,
            username=username,
            password=password or None,
            pkey=pkey,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        stdin, stdout, stderr = client.exec_command("true", timeout=timeout)
        _ = stdin.channel
        rc = stdout.channel.recv_exit_status()
        if rc != 0:
            return {
                "ok": False,
                "code": "protocol_error",
                "transport": transport,
                "duration_ms": int((time.monotonic() - t0) * 1000),
                "hint": f"Remote exec returned exit status {int(rc)} (expected 0 for true)",
            }
        hint = ""
        try:
            _, out2, _ = client.exec_command("uname -s", timeout=min(5.0, timeout))
            raw = (out2.read(64) or b"").decode("utf-8", errors="replace").strip()
            hint = raw.replace("\n", " ")[:64]
        except Exception:
            pass
        return {
            "ok": True,
            "code": "ok",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
            "hint": hint,
        }
    except paramiko.AuthenticationException:
        return {
            "ok": False,
            "code": "auth_failed",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
        }
    except paramiko.BadHostKeyException:
        return {
            "ok": False,
            "code": "host_key_mismatch",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
        }
    except paramiko.SSHException as e:
        msg = str(e).strip().replace("\n", " ")[:200]
        return {
            "ok": False,
            "code": "protocol_error",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
            "hint": f"SSHException: {msg}" if msg else "SSHException",
        }
    except socket.timeout:
        return {
            "ok": False,
            "code": "timeout",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
        }
    except OSError:
        return {
            "ok": False,
            "code": "network_unreachable",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
        }
    except Exception as e:
        msg = str(e).strip().replace("\n", " ")[:200]
        return {
            "ok": False,
            "code": "protocol_error",
            "transport": transport,
            "duration_ms": int((time.monotonic() - t0) * 1000),
            "hint": f"{type(e).__name__}: {msg}" if msg else type(e).__name__,
        }
    finally:
        try:
            client.close()
        except Exception:
            pass
