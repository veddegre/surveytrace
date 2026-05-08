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

**--inspect-envelope-only** loads ``secret_ciphertext`` for the profile and prints safe JSON metadata
(``alg``, ``v``, ``ctxh`` length, whether ``ctxh`` matches this profile id) without Paramiko, SSH, or decrypt.
Use when debugging **wrong_key_or_corrupt** (JSON parse vs context vs crypto).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import subprocess
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


def _inspect_envelope_row(envelope: str, profile_id: int) -> dict[str, Any]:
    """Safe metadata for stored secret_ciphertext (no plaintext, no raw base64 bodies)."""
    raw = (envelope or "").strip()
    out: dict[str, Any] = {
        "envelope_stripped_len": len(raw),
        "leading_non_json": None,
    }
    if not raw.startswith("{"):
        out["envelope_json_ok"] = False
        out["error"] = "envelope does not start with { (check for SQL/HTML wrapping or wrong column)"
        return out
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        out["envelope_json_ok"] = False
        out["error"] = str(e)[:240]
        return out
    if not isinstance(doc, dict):
        out["envelope_json_ok"] = False
        out["error"] = "envelope JSON is not an object"
        return out
    ctx_json = json.dumps({"credential_profile_id": int(profile_id)}, separators=(",", ":"), ensure_ascii=False)
    expected_ctxh = hashlib.sha256(ctx_json.encode("utf-8")).hexdigest()
    stored = doc.get("ctxh")
    stored_s = str(stored) if stored is not None else ""
    out.update(
        {
            "envelope_json_ok": True,
            "v": doc.get("v"),
            "alg": doc.get("alg"),
            "has_ctxh": "ctxh" in doc,
            "ctxh_len": len(stored_s),
            "stored_ctxh_matches_profile": (stored_s == expected_ctxh) if stored_s != "" else None,
            "nonce_b64_chars": len(str(doc.get("nonce", "") or "")),
            "ciphertext_b64_chars": len(str(doc.get("ciphertext", "") or "")),
            "has_tag": "tag" in doc,
            "has_aad": "aad" in doc,
        }
    )
    # Libsodium secretbox: 24-byte nonce, ciphertext includes 16-byte MAC (no decrypt here).
    _sodium_nonce = 24
    _sodium_mac = 16
    nonce_b64 = str(doc.get("nonce", "") or "")
    ct_b64 = str(doc.get("ciphertext", "") or "")
    b64: dict[str, Any] = {}
    try:
        nb = base64.b64decode(nonce_b64, validate=True)
        b64["nonce_decode_bytes"] = len(nb)
        b64["nonce_len_ok_for_sodium_secretbox"] = len(nb) == _sodium_nonce
    except (binascii.Error, ValueError) as e:
        b64["nonce_base64_error"] = type(e).__name__
    try:
        cb = base64.b64decode(ct_b64, validate=True)
        b64["ciphertext_decode_bytes"] = len(cb)
        b64["ciphertext_len_ok_for_secretbox_mac"] = len(cb) >= _sodium_mac
    except (binascii.Error, ValueError) as e:
        b64["ciphertext_base64_error"] = type(e).__name__
    out["binary_fields"] = b64
    return out


def _php_secret_status_probe(install_root: Path, php_bin: str) -> dict[str, Any] | None:
    """Run api/lib_secrets.php st_secret_status() with the current process env (same key view as cred_decrypt_cli)."""
    root = str(install_root.resolve())
    req = root + "/api/lib_secrets.php"
    code = f"chdir({root!r}); require {req!r}; echo json_encode(st_secret_status());"
    try:
        proc = subprocess.run(
            [php_bin, "-r", code],
            capture_output=True,
            timeout=15,
            env=os.environ.copy(),
            cwd=root,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"probe_error": str(e)[:220]}
    if proc.returncode != 0:
        return {
            "returncode": proc.returncode,
            "stderr_preview": (proc.stderr or "").strip().replace("\n", " ")[:220],
        }
    try:
        out = json.loads(proc.stdout or "{}")
        return out if isinstance(out, dict) else {"raw": str(out)[:120]}
    except json.JSONDecodeError:
        return {"stdout_preview": (proc.stdout or "").strip()[:220]}


def _silence_cred_probe_loggers() -> None:
    """Avoid stderr WARNING lines before JSON when piping to jq."""
    for name in ("cred_check_ssh_os_release", "cred_check_ssh_packages", "cred_secret_decrypt"):
        logging.getLogger(name).disabled = True


def main() -> int:
    ap = argparse.ArgumentParser(description="SSH cred probe (DB profile + target host)")
    ap.add_argument("--profile-id", type=int, required=True)
    ap.add_argument(
        "--host",
        default="",
        help="Target IPv4/IPv6 or hostname (required unless --inspect-envelope-only)",
    )
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
    ap.add_argument(
        "--inspect-envelope-only",
        action="store_true",
        help="Load secret_ciphertext for --profile-id and print safe envelope metadata only (no SSH, no decrypt).",
    )
    args = ap.parse_args()
    inspect_only = bool(getattr(args, "inspect_envelope_only", False))

    if bool(getattr(args, "quiet", False)):
        _silence_cred_probe_loggers()

    env_meta = _bootstrap_surveytrace_env(
        extra_files=[Path(x) for x in (args.env_file or []) if str(x).strip()],
        no_auto=bool(args.no_env_file),
    )

    inst = install_root()
    if not inspect_only:
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

    if not inspect_only and not str(args.host or "").strip():
        print(json.dumps({"ok": False, "error": "host_required", "hint": "Pass --host or use --inspect-envelope-only"}))
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

    if inspect_only:
        env_meta_ins = env_meta
        envelope_ins = str(row["secret_ciphertext"] or "")
        meta = _inspect_envelope_row(envelope_ins, int(args.profile_id))
        print(
            json.dumps(
                {
                    "ok": True,
                    "mode": "inspect_envelope_only",
                    "profile_id": int(args.profile_id),
                    "db_path": str(db_path),
                    "env_bootstrap": env_meta_ins,
                    "envelope": meta,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

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
            php_try = str(dec_diag.get("php") or "").strip() or shutil.which("php") or ""
            if php_try:
                st = _php_secret_status_probe(inst, php_try)
                if isinstance(st, dict) and ("key_fingerprint" in st or "available" in st):
                    err_doc["php_secret_status"] = {
                        "available": st.get("available"),
                        "key_fingerprint": st.get("key_fingerprint"),
                        "preferred_alg": st.get("preferred_alg"),
                        "libsodium_loaded": st.get("libsodium_loaded"),
                        "source": st.get("source"),
                    }
                elif isinstance(st, dict) and st:
                    err_doc["php_secret_status"] = st
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
            elif derr == "wrong_key_or_corrupt":
                err_doc["hint"] = (
                    "Cryptographic decrypt failed: the derived key does not open this envelope (wrong key, corrupt "
                    "ciphertext, or wrong SQLite row). On a single host, common causes are: (1) this probe uses a "
                    "different surveytrace.db than the UI (check SURVEYTRACE_DB_PATH / paths); (2) the profile secret "
                    "was saved under a different SURVEYTRACE_CRED_SECRET_KEY and the file was partially updated; "
                    "(3) DB restored from another environment. Compare php_secret_status.key_fingerprint with the "
                    "encryption status shown in the admin UI; if they differ, keys differ in practice. Easiest fix: "
                    "re-save the credential secret from the UI after confirming one canonical key in surveytrace.env."
                )
            elif derr == "envelope_context_mismatch":
                err_doc["hint"] = (
                    "The envelope was encrypted with a different binding than credential_profile_id in the decrypt "
                    "context. Ensure the profile row matches the ciphertext (re-save secret from the UI if needed)."
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
