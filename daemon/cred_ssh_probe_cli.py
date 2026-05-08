#!/usr/bin/env python3
"""
SurveyTrace — SSH diagnostic from the worker host (same Paramiko paths as cred checks).

Runs the transport handshake (UI-style AutoAddPolicy when handshake mode is on) and
ssh.linux.os_release collection (production host-key policy from env).

Does not print passwords or PEM bodies. Run on the same machine as credential_check_worker
with the same SURVEYTRACE_INSTALL_DIR / SURVEYTRACE_DB_PATH as the unit.

  SURVEYTRACE_INSTALL_DIR=/opt/surveytrace \\
    python3 daemon/cred_ssh_probe_cli.py --profile-id=12 --host=192.168.23.10

  python3 daemon/cred_ssh_probe_cli.py --db=/path/to/surveytrace.db --profile-id=12 --host=10.0.0.5 --port=2222
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

_DAEMON = Path(__file__).resolve().parent
if str(_DAEMON) not in sys.path:
    sys.path.insert(0, str(_DAEMON))

from cred_check_ssh_os_release import collect_os_release  # noqa: E402
from cred_secret_decrypt import decrypt_profile_secret  # noqa: E402
from cred_transport_ssh import run_test as run_ssh_handshake  # noqa: E402
from surveytrace_paths import install_root, main_db_path  # noqa: E402
from sqlite_pragmas import apply_surveytrace_pragmas  # noqa: E402


def _strip_ssh_out(obj: dict[str, Any]) -> dict[str, Any]:
    out = dict(obj)
    if isinstance(out.get("stdout"), (bytes, bytearray)):
        out["stdout"] = f"<{len(out['stdout'])} bytes>"
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="SSH cred probe (DB profile + target host)")
    ap.add_argument("--profile-id", type=int, required=True)
    ap.add_argument("--host", required=True, help="Target IPv4/IPv6 or hostname")
    ap.add_argument("--port", type=int, default=0, help="SSH port (0 = use principal_json port or 22)")
    ap.add_argument("--db", default="", help="SQLite path (default: SURVEYTRACE_DB_PATH or install data dir)")
    ap.add_argument("--timeout-sec", type=float, default=15.0)
    args = ap.parse_args()

    db_path = Path(args.db).expanduser().resolve() if str(args.db).strip() else main_db_path()
    if not db_path.is_file():
        print(json.dumps({"ok": False, "error": "db_not_found", "path": str(db_path)}))
        return 1

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    apply_surveytrace_pragmas(conn)

    row = conn.execute(
        """SELECT id, transport, enabled, principal_json, secret_ciphertext, deleted_at
           FROM credential_profiles WHERE id = ? LIMIT 1""",
        (args.profile_id,),
    ).fetchone()
    conn.close()

    if not row or row["deleted_at"] is not None:
        print(json.dumps({"ok": False, "error": "profile_missing", "profile_id": args.profile_id}))
        return 1
    if not int(row["enabled"] or 0):
        print(json.dumps({"ok": False, "error": "profile_disabled", "profile_id": args.profile_id}))
        return 1
    transport = str(row["transport"] or "").strip().lower()
    if transport != "ssh":
        print(json.dumps({"ok": False, "error": "not_ssh_profile", "transport": transport}))
        return 1

    try:
        principal = json.loads(str(row["principal_json"] or "{}"))
    except json.JSONDecodeError:
        principal = {}
    if not isinstance(principal, dict):
        principal = {}

    username = str(principal.get("username") or "").strip()
    if not username:
        print(json.dumps({"ok": False, "error": "principal_missing_username"}))
        return 1

    port = int(args.port) if int(args.port or 0) > 0 else 22
    if int(args.port or 0) <= 0:
        try:
            pj = int(principal.get("port") or 22)
            if 1 <= pj <= 65535:
                port = pj
        except (TypeError, ValueError):
            pass

    inst = install_root()
    envelope = str(row["secret_ciphertext"] or "")
    secret_obj: dict[str, Any] = {}
    if envelope.strip():
        plain, derr = decrypt_profile_secret(envelope=envelope, profile_id=int(args.profile_id), install_root=inst)
        if plain is None:
            print(json.dumps({"ok": False, "error": "decrypt_failed", "code": derr or "unknown"}))
            return 1
        try:
            secret_obj = json.loads(plain)
        except json.JSONDecodeError:
            print(json.dumps({"ok": False, "error": "secret_json_invalid"}))
            return 1
        if not isinstance(secret_obj, dict):
            secret_obj = {}

    payload: dict[str, Any] = {
        "transport": "ssh",
        "target_host": str(args.host).strip(),
        "port": port,
        "timeout_sec": float(max(3.0, min(60.0, args.timeout_sec))),
        "principal": {"username": username},
        "secret": {
            "password": str(secret_obj.get("password") or ""),
            "private_key": str(secret_obj.get("private_key") or ""),
            "passphrase": str(secret_obj.get("passphrase") or ""),
        },
    }

    # Handshake path (matches API transport test: AutoAddPolicy for unknown host keys).
    os.environ["SURVEYTRACE_CRED_TRANSPORT_HANDSHAKE"] = "1"
    try:
        handshake = run_ssh_handshake(payload)
    finally:
        os.environ.pop("SURVEYTRACE_CRED_TRANSPORT_HANDSHAKE", None)

    os_out = collect_os_release(
        host=str(args.host).strip(),
        port=port,
        principal=principal,
        secret=secret_obj,
        timeout_sec=float(max(3.0, min(120.0, args.timeout_sec))),
        max_stdout_bytes=65536,
        max_stderr_bytes=8192,
    )

    report = {
        "ok": bool(handshake.get("ok")) and bool(os_out.get("ok")),
        "profile_id": int(args.profile_id),
        "host": str(args.host).strip(),
        "port": port,
        "install_root": str(inst),
        "db_path": str(db_path),
        "host_key_policy_env": (os.environ.get("SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY") or "").strip() or "(default accept_new)",
        "handshake_subprocess_style": handshake,
        "os_release_collect": _strip_ssh_out(os_out),
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
