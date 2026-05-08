#!/usr/bin/env python3
"""
SurveyTrace — SSH diagnostic from the worker host (same Paramiko paths as cred checks).

Runs the transport handshake (UI-style AutoAddPolicy when handshake mode is on) and
ssh.linux.os_release collection (production host-key policy from env).

Does not print passwords or PEM bodies. Run on the same machine as credential_check_worker
with the same SURVEYTRACE_INSTALL_DIR / SURVEYTRACE_DB_PATH as the unit.

Decrypt uses the same PHP helper as the worker; **SURVEYTRACE_CRED_SECRET_KEY** must be in the
environment (systemd loads **EnvironmentFile=-/etc/surveytrace/surveytrace.env**). This CLI applies
that file automatically when present (unless **--no-env-file**), or use **--env-file** /
**SURVEYTRACE_ENV_FILE** for a custom path. **SURVEYTRACE_CRED_SECRET_KEY** and **SURVEYTRACE_PHP_CLI_BIN**
from the file always override the process (so a bad value leaked in via ``sudo`` from your shell is replaced).

The **handshake** step sets ``SURVEYTRACE_CRED_TRANSPORT_HANDSHAKE`` (AutoAddPolicy), matching the UI
transport test. **os_release_collect** uses **SURVEYTRACE_CRED_SSH_CHECK_HOST_KEY_POLICY** when set,
else **SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY** (legacy). Set ``CHECK_HOST_KEY_POLICY=accept_new``
on workers to allow first-seen keys for automated inventory (MITM risk on untrusted networks).

SSH checks need **Paramiko** in the Python interpreter you use. On production hosts, use the same
venv as **surveytrace-credential-check-worker** (not system ``python3``):

  sudo -u surveytrace SURVEYTRACE_INSTALL_DIR=/opt/surveytrace \\
    /opt/surveytrace/venv/bin/python3 /opt/surveytrace/daemon/cred_ssh_probe_cli.py --profile-id=12 --host=192.168.23.10

  /opt/surveytrace/venv/bin/python3 daemon/cred_ssh_probe_cli.py --db=/path/to/surveytrace.db --profile-id=12 --host=10.0.0.5 --port=2222

Use **--quiet** to suppress WARNING lines on stderr from cred SSH helpers (stdout JSON only).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

_DAEMON = Path(__file__).resolve().parent
if str(_DAEMON) not in sys.path:
    sys.path.insert(0, str(_DAEMON))

from cred_check_ssh_os_release import collect_os_release, cred_check_ssh_host_key_effective_label  # noqa: E402
from cred_secret_decrypt import decrypt_profile_secret  # noqa: E402
from cred_transport_ssh import run_test as run_ssh_handshake  # noqa: E402
from surveytrace_paths import install_root, main_db_path  # noqa: E402
from sqlite_pragmas import apply_surveytrace_pragmas  # noqa: E402


def _strip_ssh_out(obj: dict[str, Any]) -> dict[str, Any]:
    out = dict(obj)
    if isinstance(out.get("stdout"), (bytes, bytearray)):
        out["stdout"] = f"<{len(out['stdout'])} bytes>"
    return out


def _probe_hints(*, handshake: dict[str, Any], os_out: dict[str, Any], effective_host_key: str) -> list[str]:
    """Short operator hints when handshake and plugin disagree (common: host-key policy)."""
    hints: list[str] = []
    if not handshake.get("ok") or os_out.get("ok"):
        return hints
    det = str(os_out.get("connect_detail_safe") or "")
    dl = det.lower()
    if "known_hosts" in dl and ("not found" in dl or "not in" in dl):
        hints.append(
            "Handshake OK but os_release failed on host keys / known_hosts. "
            "For many dynamic assets, set SURVEYTRACE_CRED_SSH_CHECK_HOST_KEY_POLICY=accept_new in the worker env "
            "(MITM risk on untrusted paths — same tradeoff as first-time OpenSSH StrictHostKeyChecking=no). "
            "Or keep reject: install keys for user surveytrace (use sudo -u surveytrace bash -lc '…' so $HOME is correct, "
            "not ~surveytrace from the invoking shell)."
        )
    elif effective_host_key == "reject" and os_out.get("code") == "protocol_error":
        hints.append(
            "Cred SSH uses effective host-key policy reject; unknown hosts must be in surveytrace known_hosts, "
            "or set SURVEYTRACE_CRED_SSH_CHECK_HOST_KEY_POLICY=accept_new for automated checks."
        )
    return hints


# Always take these from a loaded env file when present (sudo often preserves the invoker's broken values).
_ENV_ALWAYS_FROM_FILE = frozenset(
    {
        "SURVEYTRACE_PHP_CLI_BIN",
        "SURVEYTRACE_PHP_CLI",
        "SURVEYTRACE_CRED_SECRET_KEY",
        "SURVEYTRACE_CRED_SECRET_KEY_STRICT",
    }
)


def _apply_simple_env_file(path: Path) -> tuple[list[str], bool]:
    """
    Merge KEY=VALUE lines into os.environ.

    Most keys: set only when missing or empty in the process. Keys in ``_ENV_ALWAYS_FROM_FILE``:
    always overwritten when the file defines a non-empty value (matches worker unit file as source of truth).
    """
    applied: list[str] = []
    if not path.is_file():
        return applied, False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if not key:
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        if key in _ENV_ALWAYS_FROM_FILE:
            if val == "":
                continue
            os.environ[key] = val
            applied.append(key)
            continue
        existing = str(os.environ.get(key, "")).strip()
        if existing != "":
            continue
        os.environ[key] = val
        applied.append(key)
    return applied, True


def _paramiko_import_error() -> BaseException | None:
    try:
        import paramiko  # noqa: F401
    except ImportError as e:
        return e
    return None


def _bootstrap_surveytrace_env(*, extra_files: list[Path], no_auto: bool) -> dict[str, Any]:
    """Load same-style env files as systemd units so PHP decrypt sees SURVEYTRACE_CRED_SECRET_KEY."""
    meta: dict[str, Any] = {"files_tried": [], "keys_set": []}
    paths: list[Path] = []
    for p in extra_files:
        paths.append(p.expanduser().resolve())
    raw_ef = (os.environ.get("SURVEYTRACE_ENV_FILE") or "").strip()
    if raw_ef:
        paths.append(Path(raw_ef).expanduser().resolve())
    if not no_auto:
        paths.append(Path("/etc/surveytrace/surveytrace.env"))
    seen: set[str] = set()
    for p in paths:
        key = str(p)
        if key in seen:
            continue
        seen.add(key)
        meta["files_tried"].append(str(p))
        keys, ok = _apply_simple_env_file(p)
        if ok:
            meta["keys_set"].extend(keys)
    return meta


def _silence_cred_probe_loggers() -> None:
    """Avoid stderr WARNING lines before JSON when piping to jq."""
    for name in ("cred_check_ssh_os_release", "cred_check_ssh_packages", "cred_secret_decrypt"):
        logging.getLogger(name).disabled = True


def main() -> int:
    ap = argparse.ArgumentParser(description="SSH cred probe (DB profile + target host)")
    ap.add_argument("--profile-id", type=int, required=True)
    ap.add_argument("--host", required=True, help="Target IPv4/IPv6 or hostname")
    ap.add_argument("--port", type=int, default=0, help="SSH port (0 = use principal_json port or 22)")
    ap.add_argument("--db", default="", help="SQLite path (default: SURVEYTRACE_DB_PATH or install data dir)")
    ap.add_argument("--timeout-sec", type=float, default=15.0)
    ap.add_argument(
        "--env-file",
        action="append",
        default=[],
        metavar="PATH",
        help="Optional env file to load before decrypt (repeatable). Applied before SURVEYTRACE_ENV_FILE and /etc/surveytrace/surveytrace.env unless --no-env-file.",
    )
    ap.add_argument(
        "--no-env-file",
        action="store_true",
        help="Do not auto-load /etc/surveytrace/surveytrace.env (only already-exported vars and --env-file).",
    )
    ap.add_argument(
        "--quiet",
        action="store_true",
        help="Disable WARNING logs from cred SSH/decrypt helpers on stderr (JSON remains on stdout).",
    )
    args = ap.parse_args()

    if bool(getattr(args, "quiet", False)):
        _silence_cred_probe_loggers()

    env_meta = _bootstrap_surveytrace_env(
        extra_files=[Path(x) for x in (args.env_file or []) if str(x).strip()],
        no_auto=bool(args.no_env_file),
    )

    inst = install_root()
    pi_err = _paramiko_import_error()
    if pi_err is not None:
        script_path = Path(__file__).resolve()
        vpy = inst / "venv" / "bin" / "python3"
        suggested = (
            f"sudo -u surveytrace SURVEYTRACE_INSTALL_DIR={inst} "
            f"{vpy} {script_path} --profile-id={args.profile_id} --host={args.host}"
        )
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "dependency_missing",
                    "missing": "paramiko",
                    "python_interpreter": sys.executable,
                    "venv_python_exists": vpy.is_file(),
                    "venv_python": str(vpy),
                    "import_error": str(pi_err)[:300],
                    "hint": "Paramiko is required for SSH in this process. The cred worker uses the SurveyTrace venv; run this probe with that interpreter (see venv_python).",
                    "suggested_command": suggested if vpy.is_file() else None,
                    "env_bootstrap": env_meta,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 1

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

    envelope = str(row["secret_ciphertext"] or "")
    secret_obj: dict[str, Any] = {}
    if envelope.strip():
        plain, derr, dec_diag = decrypt_profile_secret(
            envelope=envelope, profile_id=int(args.profile_id), install_root=inst
        )
        if plain is None:
            err_doc: dict[str, Any] = {
                "ok": False,
                "error": "decrypt_failed",
                "code": derr or "unknown",
                "env_bootstrap": env_meta,
                "decrypt_diagnostic": dec_diag,
            }
            if derr == "encryption_unavailable":
                err_doc["hint"] = (
                    "PHP decrypt needs SURVEYTRACE_CRED_SECRET_KEY (see api/lib_secrets.php). "
                    "surveytrace-credential-check-worker.service uses EnvironmentFile=-/etc/surveytrace/surveytrace.env. "
                    "Re-run without --no-env-file so this CLI can load that file, or: "
                    "set -a && source /etc/surveytrace/surveytrace.env && set +a && python3 …"
                )
            elif derr == "dependency_missing":
                err_doc["hint"] = (
                    "PHP CLI missing or not executable for decrypt. Set SURVEYTRACE_PHP_CLI_BIN in "
                    "/etc/surveytrace/surveytrace.env (same path as sudoers for cred_secret_ops) or ensure php is on PATH."
                )
            elif derr == "decrypt_failed":
                err_doc["hint"] = (
                    "cred_decrypt_cli.php failed (see decrypt_diagnostic: php binary, returncode, stderr_preview). "
                    "Often: SURVEYTRACE_CRED_SECRET_KEY differs from the host that encrypted the profile, or the PHP "
                    "binary lacks required extensions compared to the web stack."
                )
            print(json.dumps(err_doc, indent=2, ensure_ascii=False))
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

    hk_eff = cred_check_ssh_host_key_effective_label()
    report = {
        "ok": bool(handshake.get("ok")) and bool(os_out.get("ok")),
        "profile_id": int(args.profile_id),
        "host": str(args.host).strip(),
        "port": port,
        "install_root": str(inst),
        "db_path": str(db_path),
        "env_bootstrap": env_meta,
        "cred_secret_key_configured": bool(str(os.environ.get("SURVEYTRACE_CRED_SECRET_KEY", "")).strip()),
        "cred_check_host_key_effective": hk_eff,
        "SURVEYTRACE_CRED_SSH_CHECK_HOST_KEY_POLICY": os.environ.get("SURVEYTRACE_CRED_SSH_CHECK_HOST_KEY_POLICY"),
        "SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY": os.environ.get("SURVEYTRACE_CRED_SSH_TEST_HOST_KEY_POLICY"),
        "host_key_policy_env": hk_eff,
        "probe_hints": _probe_hints(handshake=handshake, os_out=os_out, effective_host_key=hk_eff),
        "handshake_subprocess_style": handshake,
        "os_release_collect": _strip_ssh_out(os_out),
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
