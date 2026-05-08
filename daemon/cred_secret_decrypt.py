"""
Decrypt credential profile envelopes via daemon/cred_decrypt_cli.php (matches api/lib_secrets.php).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def _resolve_php_cli() -> str | None:
    """Prefer SURVEYTRACE_PHP_CLI_BIN from surveytrace.env (same as setup/deploy), else PATH."""
    for key in ("SURVEYTRACE_PHP_CLI_BIN", "SURVEYTRACE_PHP_CLI"):
        raw = (os.environ.get(key) or "").strip()
        if not raw:
            continue
        p = Path(raw).expanduser()
        try:
            if p.is_file() and os.access(p, os.X_OK):
                return str(p)
        except OSError:
            continue
    return shutil.which("php")


def _stderr_preview_safe(raw: bytes, *, cap: int = 220) -> str:
    s = raw.decode("utf-8", errors="replace").strip().replace("\r", " ").replace("\n", " ")
    return s[:cap]


def decrypt_profile_secret(
    *, envelope: str, profile_id: int, install_root: Path
) -> tuple[str | None, str | None, dict[str, Any]]:
    """
    Returns (plaintext_json_string, None, {}) on success, or (None, error_code, diagnostic) on failure.

    error_code: decrypt_failed | encryption_unavailable | dependency_missing

    ``diagnostic`` is safe for operator logs (php path, return code, bounded stderr); never secrets.
    """
    diag: dict[str, Any] = {}
    env = (envelope or "").strip()
    if env == "":
        return None, "decrypt_failed", diag
    php = _resolve_php_cli()
    diag["php"] = php or "(none)"
    if not php:
        log.warning("php not on PATH — cannot decrypt profile secret")
        return None, "dependency_missing", diag
    cli = install_root / "daemon" / "cred_decrypt_cli.php"
    if not cli.is_file():
        log.warning("cred_decrypt_cli.php missing at %s", cli)
        return None, "dependency_missing", diag
    ctx = json.dumps({"credential_profile_id": int(profile_id)}, separators=(",", ":"), ensure_ascii=False)
    try:
        proc = subprocess.run(
            [php, str(cli), ctx],
            input=env.encode("utf-8"),
            capture_output=True,
            timeout=30,
            cwd=str(install_root),
        )
    except subprocess.TimeoutExpired:
        diag["returncode"] = None
        diag["stderr_preview"] = "timeout waiting for cred_decrypt_cli.php"
        return None, "decrypt_failed", diag
    except OSError as e:
        log.warning("decrypt subprocess: %s", e)
        diag["stderr_preview"] = str(e).strip()[:220]
        return None, "dependency_missing", diag
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()[:500]
        diag["returncode"] = int(proc.returncode)
        diag["stderr_preview"] = _stderr_preview_safe(proc.stderr or b"", cap=220)
        token = (err.splitlines()[0].strip() if err else "") or ""
        # cred_decrypt_cli.php emits single-line tokens (see st_cred_decrypt_cli_error_token).
        _detail_codes = frozenset(
            {
                "wrong_key_or_corrupt",
                "envelope_context_mismatch",
                "invalid_envelope_encoding",
                "invalid_envelope",
                "invalid_gcm_tag",
                "unsupported_envelope_algorithm",
                "envelope_json_invalid",
                "context_json_invalid",
                "decrypt_unknown",
            }
        )
        if token == "encryption_unavailable" or "encryption_unavailable" in err:
            return None, "encryption_unavailable", diag
        if token == "dependency_missing" or "dependency_missing" in err:
            return None, "dependency_missing", diag
        if token in _detail_codes:
            return None, ("decrypt_failed" if token == "decrypt_unknown" else token), diag
        # Legacy PHP wrote the literal string "decrypt_failed" for all failures.
        return None, "decrypt_failed", diag
    out = (proc.stdout or b"").decode("utf-8", errors="replace")
    return out, None, {}
