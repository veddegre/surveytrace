"""
Decrypt credential profile envelopes via daemon/cred_decrypt_cli.php (matches api/lib_secrets.php).
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)


def decrypt_profile_secret(*, envelope: str, profile_id: int, install_root: Path) -> tuple[str | None, str | None]:
    """
    Returns (plaintext_json_string, None) on success, or (None, error_code) on failure.
    error_code: decrypt_failed | encryption_unavailable
    """
    env = (envelope or "").strip()
    if env == "":
        return None, "decrypt_failed"
    php = shutil.which("php")
    if not php:
        log.warning("php not on PATH — cannot decrypt profile secret")
        return None, "decrypt_failed"
    cli = install_root / "daemon" / "cred_decrypt_cli.php"
    if not cli.is_file():
        log.warning("cred_decrypt_cli.php missing at %s", cli)
        return None, "decrypt_failed"
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
        return None, "decrypt_failed"
    except OSError as e:
        log.warning("decrypt subprocess: %s", e)
        return None, "decrypt_failed"
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", errors="replace").strip()[:500]
        if "not configured" in err.lower() or "Credential encryption is not configured" in err:
            return None, "encryption_unavailable"
        # Do not log stderr — may contain sensitive hints from PHP/OpenSSL in some builds.
        return None, "decrypt_failed"
    out = (proc.stdout or b"").decode("utf-8", errors="replace")
    return out, None
