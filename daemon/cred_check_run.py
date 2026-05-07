"""
Credentialed check run execution (slices 7–9): SSH os_release + package_inventory, SNMPv3 device_identity;
other plugins stay not_implemented / transport-mismatch failed rows.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
from typing import Any, Callable

from surveytrace_paths import install_root

from cred_check_snmp_identity import (
    build_normalized_identity,
    classify_identity_partial,
    collect_snmp_device_identity,
)
from cred_check_ssh_os_release import collect_os_release
from cred_check_ssh_packages import collect_package_inventory, parse_tabular_package_lines
from cred_secret_decrypt import decrypt_profile_secret

import recon_observations as recon

log = logging.getLogger(__name__)

OS_RELEASE_KEY = "ssh.linux.os_release"
OS_RELEASE_VER = "1.0.0"
PKG_KEY = "ssh.linux.package_inventory"
PKG_VER = "1.0.0"
MAX_PKG_ROWS_STORE = 2000
PKG_NAME_MAX = 200
PKG_VER_MAX = 200
PKG_ARCH_MAX = 64
SNMP_KEY = "snmpv3.device_identity"
SNMP_VER = "1.0.0"

# Drop keys that often carry secrets; cap size so normalized_json cannot balloon.
_OS_RELEASE_SENSITIVE_KEY = re.compile(r"(?i)(password|passwd|secret|token|apikey|api_key|private_key|credential)")
_OS_RELEASE_MAX_KEYS = 64
_OS_RELEASE_MAX_KEY_LEN = 128
_OS_RELEASE_MAX_VAL_LEN = 1024


def _sanitize_os_release_for_result(kv: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for i, (k, v) in enumerate(kv.items()):
        if i >= _OS_RELEASE_MAX_KEYS:
            break
        ks = str(k).strip()[: _OS_RELEASE_MAX_KEY_LEN]
        if not ks or _OS_RELEASE_SENSITIVE_KEY.search(ks):
            continue
        out[ks] = str(v).strip()[: _OS_RELEASE_MAX_VAL_LEN]
    return out


def _parse_os_release_text(data: bytes) -> tuple[dict[str, str] | None, str | None]:
    try:
        txt = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        txt = data.decode("utf-8", errors="replace")
    kv: dict[str, str] = {}
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k:
            kv[k] = v
    if not kv:
        return None, "normalize_error"
    return kv, None


def _os_release_display(kv: dict[str, str]) -> str:
    pn = (kv.get("PRETTY_NAME") or "").strip()
    if pn:
        return pn[:2000]
    parts: list[str] = []
    if (kv.get("NAME") or "").strip():
        parts.append(kv["NAME"].strip())
    if (kv.get("VERSION_ID") or "").strip():
        parts.append(kv["VERSION_ID"].strip())
    elif (kv.get("VERSION") or "").strip():
        parts.append(kv["VERSION"].strip())
    s = " ".join(parts).strip()
    if s:
        return s[:2000]
    return ((kv.get("ID") or "").strip() or "linux")[:2000]


def _selection_includes_plugin(plugins: list[dict[str, Any]], plugin_key: str, default_ver: str) -> bool:
    for p in plugins:
        pk = str(p.get("plugin_key") or "").strip()
        ver = str(p.get("version") or "").strip() or default_ver
        if pk == plugin_key and ver in ("", default_ver):
            return True
    return False


def _load_plugin_caps(conn: sqlite3.Connection, plugin_key: str, plugin_version: str) -> tuple[int, int]:
    """timeout_ms and max_stdout from registry manifest (defaults by plugin)."""
    if plugin_key == PKG_KEY:
        timeout_ms, out_max = 120_000, 5_242_880
    elif plugin_key == SNMP_KEY:
        timeout_ms, out_max = 10_000, 131_072
    else:
        timeout_ms, out_max = 15_000, 65_536
    try:
        row = conn.execute(
            "SELECT manifest_json FROM credential_check_plugins WHERE plugin_key = ? AND version = ? LIMIT 1",
            (plugin_key, plugin_version),
        ).fetchone()
        if not row:
            return timeout_ms, out_max
        raw = row["manifest_json"] if isinstance(row, sqlite3.Row) else row[0]
        if not raw:
            return timeout_ms, out_max
        doc = json.loads(str(raw))
        if isinstance(doc, dict):
            t_def = int(doc.get("timeout_ms_default") or timeout_ms)
            t_max = int(doc.get("timeout_ms_max") or 600_000)
            timeout_ms = max(3000, min(t_max, max(3000, t_def)))
            o = int(doc.get("output_size_bytes_max") or out_max)
            out_max = max(4096, min(6_291_456, o))
    except (TypeError, ValueError, json.JSONDecodeError, sqlite3.Error):
        pass
    return timeout_ms, out_max


def _json_pair(norm: dict[str, Any], met: dict[str, Any]) -> tuple[str, str]:
    try:
        return (
            json.dumps(norm, separators=(",", ":"), ensure_ascii=False),
            json.dumps(met, separators=(",", ":"), ensure_ascii=False),
        )
    except (TypeError, ValueError):
        return "{}", "{}"


def _insert_result(
    conn: sqlite3.Connection,
    run_id: int,
    tid: int,
    aid: int,
    pkey: str,
    pver: str,
    status: str,
    norm: dict[str, Any],
    met: dict[str, Any],
) -> int:
    nj, mj = _json_pair(norm, met)
    conn.execute(
        """INSERT INTO credential_check_results (run_id, target_id, asset_id, plugin_key, plugin_version, status, normalized_json, metrics_json)
           VALUES (?,?,?,?,?,?,?,?)""",
        (run_id, tid, aid, pkey, pver, status, nj, mj),
    )
    return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])


def _insert_stdout_artifact(conn: sqlite3.Connection, result_id: int, raw: bytes, cap: int = 32768) -> None:
    if not raw:
        return
    snippet = bytes(raw)[: min(cap, len(raw))]
    digest = hashlib.sha256(snippet).hexdigest()
    conn.execute(
        """INSERT INTO credential_check_artifacts (result_id, kind, storage_path, "blob", sha256, size_bytes, redaction_version)
           VALUES (?,?,NULL,?,?,?,1)""",
        (result_id, "stdout", snippet, digest, len(snippet)),
    )


def _insert_snmp_identity_json_artifact(conn: sqlite3.Connection, result_id: int, doc: dict[str, Any], cap: int = 4096) -> None:
    try:
        raw = json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8", errors="replace")[:cap]
    except (TypeError, ValueError):
        return
    if not raw:
        return
    digest = hashlib.sha256(raw).hexdigest()
    conn.execute(
        """INSERT INTO credential_check_artifacts (result_id, kind, storage_path, "blob", sha256, size_bytes, redaction_version)
           VALUES (?,?,NULL,?,?,?,1)""",
        (result_id, "snmp_identity_json", raw, digest, len(raw)),
    )


def _audit(conn: sqlite3.Connection, action: str, details: dict[str, Any]) -> None:
    try:
        conn.execute(
            """
            INSERT INTO user_audit_log
                (actor_user_id, actor_username, target_user_id, target_username, action, details_json, source_ip)
            VALUES
                (NULL, 'system', NULL, NULL, ?, ?, '127.0.0.1')
            """,
            (action, json.dumps(dict(details), separators=(",", ":"), ensure_ascii=False)),
        )
        conn.commit()
    except sqlite3.Error:
        try:
            conn.rollback()
        except sqlite3.Error:
            pass


def _mark_all_pending(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    status: str,
    error_code: str,
    message: str,
) -> int:
    cur = conn.execute(
        "SELECT COUNT(*) FROM credential_check_run_targets WHERE run_id = ? AND status = 'pending'",
        (run_id,),
    )
    n = int(cur.fetchone()[0])
    if n < 1:
        return 0
    conn.execute(
        """UPDATE credential_check_run_targets SET status = ?, error_code = ?, error_message_safe = ?,
            finished_at = datetime('now') WHERE run_id = ? AND status = 'pending'""",
        (status, error_code, message[:500], run_id),
    )
    conn.commit()
    return n


def process_cred_check_run(
    conn: sqlite3.Connection,
    *,
    run_id: int,
    jid: int,
    cancel_requested: Callable[[], bool],
    audit: Callable[[sqlite3.Connection, str, dict[str, Any]], None],
) -> dict[str, Any]:
    """
    Process all pending targets for a run. Commits internally. Returns aggregate summary for summary_json.
    """
    row_job = conn.execute(
        """SELECT j.id, j.credential_profile_id, j.plugin_selection_json, j.policy_json, j.enabled
           FROM credential_check_jobs j
           JOIN credential_check_runs r ON r.job_id = j.id
           WHERE r.id = ? LIMIT 1""",
        (run_id,),
    ).fetchone()
    if not row_job:
        return {"error": "job_missing", "targets_total": 0}

    job_id = int(row_job["id"])
    profile_id = int(row_job["credential_profile_id"] or 0)
    try:
        plugins_raw = json.loads(str(row_job["plugin_selection_json"] or "[]"))
    except (TypeError, ValueError, json.JSONDecodeError):
        plugins_raw = []
    if not isinstance(plugins_raw, list):
        plugins_raw = []
    plugins: list[dict[str, Any]] = [x for x in plugins_raw if isinstance(x, dict)]

    policy = {}
    try:
        policy = json.loads(str(row_job["policy_json"] or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        policy = {}
    if not isinstance(policy, dict):
        policy = {}
    policy_timeout_ms = int(policy.get("timeout_ms") or 600_000)
    policy_timeout_ms = max(5000, min(3_600_000, policy_timeout_ms))

    caps_os = _load_plugin_caps(conn, OS_RELEASE_KEY, OS_RELEASE_VER)
    caps_pkg = _load_plugin_caps(conn, PKG_KEY, PKG_VER)
    caps_snmp = _load_plugin_caps(conn, SNMP_KEY, SNMP_VER)
    op_to_os = min(policy_timeout_ms, caps_os[0]) / 1000.0
    op_to_pkg = min(policy_timeout_ms, caps_pkg[0]) / 1000.0
    op_to_snmp = min(policy_timeout_ms, caps_snmp[0]) / 1000.0
    max_out_os = caps_os[1]
    max_out_pkg = caps_pkg[1]

    if not int(row_job["enabled"] or 0):
        sk = _mark_all_pending(conn, run_id, status="skipped", error_code="job_disabled", message="job disabled")
        return {
            "error": "job_disabled",
            "targets_total": sk,
            "targets_skipped": sk,
            "executor": "credential_check_worker",
            "slice": 9,
            "job_id": job_id,
        }

    prof = conn.execute(
        """SELECT id, transport, enabled, principal_json, secret_ciphertext, deleted_at
           FROM credential_profiles WHERE id = ? LIMIT 1""",
        (profile_id,),
    ).fetchone()
    if not prof or prof["deleted_at"] is not None:
        sk = _mark_all_pending(conn, run_id, status="skipped", error_code="dependency_missing", message="profile missing")
        return {
            "error": "profile_missing",
            "targets_total": sk,
            "targets_skipped": sk,
            "executor": "credential_check_worker",
            "slice": 9,
            "job_id": job_id,
        }
    if not int(prof["enabled"] or 0):
        sk = _mark_all_pending(conn, run_id, status="skipped", error_code="profile_disabled", message="profile disabled")
        return {
            "error": "profile_disabled",
            "targets_total": sk,
            "targets_skipped": sk,
            "executor": "credential_check_worker",
            "slice": 9,
            "job_id": job_id,
        }

    transport = str(prof["transport"] or "").strip().lower()
    try:
        principal = json.loads(str(prof["principal_json"] or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        principal = {}
    if not isinstance(principal, dict):
        principal = {}

    placeholder_only = (os.environ.get("SURVEYTRACE_CRED_CHECK_PLACEHOLDER_ONLY") or "").strip() in (
        "1",
        "true",
        "yes",
    )
    want_os = _selection_includes_plugin(plugins, OS_RELEASE_KEY, OS_RELEASE_VER)
    want_pkg = _selection_includes_plugin(plugins, PKG_KEY, PKG_VER)
    want_snmp = _selection_includes_plugin(plugins, SNMP_KEY, SNMP_VER)
    want_ssh_exec = want_os or want_pkg
    want_any_exec = want_ssh_exec or want_snmp

    can_ssh = transport == "ssh"
    can_snmp = transport == "snmpv3"

    all_plugin_tags = [f"{p.get('plugin_key')}@{p.get('version') or '1.0.0'}" for p in plugins]
    executable_tags: list[str] = []
    if not placeholder_only:
        if can_ssh and want_os:
            executable_tags.append(f"{OS_RELEASE_KEY}@{OS_RELEASE_VER}")
        if can_ssh and want_pkg:
            executable_tags.append(f"{PKG_KEY}@{PKG_VER}")
        if can_snmp and want_snmp:
            executable_tags.append(f"{SNMP_KEY}@{SNMP_VER}")
    placeholder_plugin_tags = [x for x in all_plugin_tags if x not in executable_tags]

    targets = conn.execute(
        "SELECT id, asset_id, status FROM credential_check_run_targets WHERE run_id = ? ORDER BY id ASC",
        (run_id,),
    ).fetchall()

    counts: dict[str, Any] = {
        "targets_total": len(targets),
        "targets_completed": 0,
        "targets_failed": 0,
        "targets_skipped": 0,
        "os_release_attempted": 0,
        "os_release_ok": 0,
        "package_inventory_attempted": 0,
        "package_inventory_ok": 0,
        "snmp_identity_attempted": 0,
        "snmp_identity_ok": 0,
        "placeholder_only": placeholder_only,
        "plugins_placeholder": placeholder_plugin_tags,
    }

    inst = install_root()

    for t in targets:
        tid = int(t["id"])
        aid = int(t["asset_id"])
        tst = str(t["status"])
        if tst != "pending":
            continue

        if cancel_requested():
            conn.execute(
                """UPDATE credential_check_run_targets SET status = 'skipped', error_code = 'user_cancelled',
                    error_message_safe = 'cancelled', finished_at = datetime('now') WHERE id = ? AND status = 'pending'""",
                (tid,),
            )
            counts["targets_skipped"] += 1
            conn.commit()
            continue

        conn.execute(
            "UPDATE credential_check_run_targets SET status = 'running', started_at = datetime('now'), error_code = NULL, error_message_safe = NULL WHERE id = ? AND status = 'pending'",
            (tid,),
        )
        conn.commit()
        audit(conn, "credential_check.target_started", {"run_id": run_id, "target_row_id": tid, "asset_id": aid})

        def skip_placeholder(code: str, msg: str) -> None:
            conn.execute(
                """UPDATE credential_check_run_targets SET status = 'skipped', error_code = ?, error_message_safe = ?,
                    finished_at = datetime('now') WHERE id = ?""",
                (code, msg[:500], tid),
            )
            counts["targets_skipped"] += 1
            conn.commit()
            audit(
                conn,
                "credential_check.target_completed",
                {"run_id": run_id, "target_row_id": tid, "asset_id": aid, "outcome": "skipped", "error_code": code},
            )

        if placeholder_only or not want_any_exec:
            skip_placeholder("not_implemented", "placeholder or no executable plugin for this worker mode")
            continue

        if transport not in ("ssh", "snmpv3"):
            conn.execute(
                """UPDATE credential_check_run_targets SET status = 'failed', error_code = 'unsupported_transport',
                    error_message_safe = ?, finished_at = datetime('now') WHERE id = ?""",
                (f"profile transport {transport}", tid),
            )
            counts["targets_failed"] += 1
            conn.commit()
            audit(conn, "credential_check.target_failed", {"run_id": run_id, "target_row_id": tid, "code": "unsupported_transport"})
            continue

        asset = conn.execute("SELECT ip, hostname FROM assets WHERE id = ? LIMIT 1", (aid,)).fetchone()
        if not asset:
            conn.execute(
                """UPDATE credential_check_run_targets SET status = 'failed', error_code = 'dependency_missing',
                    error_message_safe = 'asset missing', finished_at = datetime('now') WHERE id = ?""",
                (tid,),
            )
            counts["targets_failed"] += 1
            conn.commit()
            audit(conn, "credential_check.target_failed", {"run_id": run_id, "target_row_id": tid, "code": "dependency_missing"})
            continue

        host = str(asset["ip"] or "").strip()
        if not host:
            conn.execute(
                """UPDATE credential_check_run_targets SET status = 'failed', error_code = 'invalid_profile',
                    error_message_safe = 'asset has no ip', finished_at = datetime('now') WHERE id = ?""",
                (tid,),
            )
            counts["targets_failed"] += 1
            conn.commit()
            audit(conn, "credential_check.target_failed", {"run_id": run_id, "target_row_id": tid, "code": "invalid_profile"})
            continue

        port_ssh = 22
        try:
            pj = int(principal.get("port") or 22)
            if 1 <= pj <= 65535:
                port_ssh = pj
        except (TypeError, ValueError):
            pass
        port_snmp = 161
        try:
            pj_s = int(principal.get("port") or 161)
            if 1 <= pj_s <= 65535:
                port_snmp = pj_s
        except (TypeError, ValueError):
            pass

        envelope = str(prof["secret_ciphertext"] or "")
        secret_obj: dict[str, Any] = {}
        if envelope.strip():
            plain, derr = decrypt_profile_secret(envelope=envelope, profile_id=profile_id, install_root=inst)
            if plain is None:
                code = derr or "decrypt_failed"
                safe = "could not decrypt secret" if code == "decrypt_failed" else "encryption not configured on worker host"
                conn.execute(
                    """UPDATE credential_check_run_targets SET status = 'failed', error_code = ?, error_message_safe = ?,
                        finished_at = datetime('now') WHERE id = ?""",
                    (code, safe[:500], tid),
                )
                counts["targets_failed"] += 1
                conn.commit()
                audit(conn, "credential_check.target_failed", {"run_id": run_id, "target_row_id": tid, "code": code})
                continue
            try:
                secret_obj = json.loads(plain)
            except (TypeError, ValueError, json.JSONDecodeError):
                conn.execute(
                    """UPDATE credential_check_run_targets SET status = 'failed', error_code = 'decrypt_failed',
                        error_message_safe = 'secret json invalid', finished_at = datetime('now') WHERE id = ?""",
                    (tid,),
                )
                counts["targets_failed"] += 1
                conn.commit()
                audit(conn, "credential_check.target_failed", {"run_id": run_id, "target_row_id": tid, "code": "decrypt_failed"})
                continue
            if not isinstance(secret_obj, dict):
                secret_obj = {}

        def _plugin_transport_fail(pkey: str, pver: str) -> None:
            _insert_result(
                conn,
                run_id,
                tid,
                aid,
                pkey,
                pver,
                "failed",
                {"source": "credentialed_check", "error_code": "unsupported_transport"},
                {"plugin_key": pkey, "plugin_version": pver},
            )

        if want_os and not can_ssh:
            _plugin_transport_fail(OS_RELEASE_KEY, OS_RELEASE_VER)
        if want_pkg and not can_ssh:
            _plugin_transport_fail(PKG_KEY, PKG_VER)
        if want_snmp and not can_snmp:
            _plugin_transport_fail(SNMP_KEY, SNMP_VER)

        auth_failed_skip_pkg = False

        # ---- ssh.linux.os_release ----
        if can_ssh and want_os:
            counts["os_release_attempted"] += 1
            ssh_out = collect_os_release(
                host=host,
                port=port_ssh,
                principal=principal,
                secret=secret_obj,
                timeout_sec=op_to_os,
                max_stdout_bytes=max_out_os,
                max_stderr_bytes=8192,
            )
            if not ssh_out.get("ok"):
                code = str(ssh_out.get("code") or "command_failed")
                if code not in (
                    "auth_failed",
                    "timeout",
                    "command_failed",
                    "output_too_large",
                    "protocol_error",
                    "invalid_profile",
                    "network_unreachable",
                    "host_key_mismatch",
                    "dependency_missing",
                ):
                    code = "command_failed"
                if code == "auth_failed":
                    auth_failed_skip_pkg = True
                _insert_result(
                    conn,
                    run_id,
                    tid,
                    aid,
                    OS_RELEASE_KEY,
                    OS_RELEASE_VER,
                    "failed",
                    {"source": "credentialed_check", "error_code": code},
                    {
                        "plugin_key": OS_RELEASE_KEY,
                        "plugin_version": OS_RELEASE_VER,
                        "duration_ms": ssh_out.get("duration_ms"),
                        "stderr_snippet_len": len((ssh_out.get("stderr_snippet") or "")),
                        "exit_code": ssh_out.get("exit_code"),
                    },
                )
            else:
                raw_stdout = ssh_out.get("stdout")
                if not isinstance(raw_stdout, (bytes, bytearray)) or len(raw_stdout) == 0:
                    _insert_result(
                        conn,
                        run_id,
                        tid,
                        aid,
                        OS_RELEASE_KEY,
                        OS_RELEASE_VER,
                        "failed",
                        {"source": "credentialed_check", "error_code": "command_failed"},
                        {
                            "plugin_key": OS_RELEASE_KEY,
                            "plugin_version": OS_RELEASE_VER,
                            "duration_ms": ssh_out.get("duration_ms"),
                            "stderr_snippet_len": len((ssh_out.get("stderr_snippet") or "")),
                            "exit_code": ssh_out.get("exit_code"),
                        },
                    )
                else:
                    kv, perr = _parse_os_release_text(bytes(raw_stdout))
                    if kv is None:
                        _insert_result(
                            conn,
                            run_id,
                            tid,
                            aid,
                            OS_RELEASE_KEY,
                            OS_RELEASE_VER,
                            "failed",
                            {"source": "credentialed_check", "error_code": perr or "normalize_error"},
                            {
                                "plugin_key": OS_RELEASE_KEY,
                                "plugin_version": OS_RELEASE_VER,
                                "duration_ms": ssh_out.get("duration_ms"),
                                "stderr_snippet_len": len((ssh_out.get("stderr_snippet") or "")),
                                "exit_code": ssh_out.get("exit_code"),
                            },
                        )
                    else:
                        display = _os_release_display(kv)
                        slug, _label = recon.normalize_os_text_public(display)
                        norm_os = slug if slug else "linux_unknown"
                        kv_safe = _sanitize_os_release_for_result(kv)
                        normalized_doc: dict[str, Any] = {
                            "os_release": kv_safe,
                            "normalized_os": norm_os,
                            "source": "credentialed_check",
                        }
                        metrics_doc: dict[str, Any] = {
                            "duration_ms": ssh_out.get("duration_ms"),
                            "plugin_key": OS_RELEASE_KEY,
                            "plugin_version": OS_RELEASE_VER,
                            "stderr_snippet_len": len((ssh_out.get("stderr_snippet") or "")),
                            "exit_code": ssh_out.get("exit_code"),
                        }
                        rid = _insert_result(conn, run_id, tid, aid, OS_RELEASE_KEY, OS_RELEASE_VER, "success", normalized_doc, metrics_doc)
                        _insert_stdout_artifact(conn, rid, bytes(raw_stdout))
                        prov = {
                            "plugin_key": OS_RELEASE_KEY,
                            "plugin_version": OS_RELEASE_VER,
                            "run_id": run_id,
                            "target_row_id": tid,
                            "result_id": rid,
                        }
                        ref = f"run:{run_id}:target:{tid}:{OS_RELEASE_KEY}@{OS_RELEASE_VER}"
                        if recon.upsert_credentialed_check_os_observation(
                            conn,
                            asset_id=aid,
                            raw_value=display,
                            source_object_ref=ref,
                            provenance=prov,
                        ):
                            audit(
                                conn,
                                "credential_check.observation_written",
                                {"run_id": run_id, "target_row_id": tid, "asset_id": aid, "observation_type": "os_version_observed"},
                            )
                        counts["os_release_ok"] += 1

        if cancel_requested():
            conn.execute(
                """UPDATE credential_check_run_targets SET status = 'skipped', error_code = 'user_cancelled',
                    error_message_safe = 'cancelled', finished_at = datetime('now') WHERE id = ? AND status = 'running'""",
                (tid,),
            )
            counts["targets_skipped"] += 1
            conn.commit()
            audit(conn, "credential_check.target_completed", {"run_id": run_id, "target_row_id": tid, "outcome": "cancelled"})
            continue

        # ---- ssh.linux.package_inventory ----
        if can_ssh and want_pkg:
            counts["package_inventory_attempted"] += 1
            if auth_failed_skip_pkg:
                _insert_result(
                    conn,
                    run_id,
                    tid,
                    aid,
                    PKG_KEY,
                    PKG_VER,
                    "failed",
                    {"source": "credentialed_check", "error_code": "auth_failed"},
                    {"plugin_key": PKG_KEY, "plugin_version": PKG_VER},
                )
            else:
                pkg_out = collect_package_inventory(
                    host=host,
                    port=port_ssh,
                    principal=principal,
                    secret=secret_obj,
                    timeout_sec=op_to_pkg,
                    max_stdout_bytes=max_out_pkg,
                    max_stderr_bytes=8192,
                )
                if not pkg_out.get("ok"):
                    code = str(pkg_out.get("code") or "command_failed")
                    if code not in (
                        "auth_failed",
                        "timeout",
                        "command_failed",
                        "output_too_large",
                        "protocol_error",
                        "invalid_profile",
                        "network_unreachable",
                        "host_key_mismatch",
                        "unsupported_os",
                        "dependency_missing",
                    ):
                        code = "command_failed"
                    _insert_result(
                        conn,
                        run_id,
                        tid,
                        aid,
                        PKG_KEY,
                        PKG_VER,
                        "failed",
                        {"source": "credentialed_check", "error_code": code},
                        {
                            "plugin_key": PKG_KEY,
                            "plugin_version": PKG_VER,
                            "duration_ms": pkg_out.get("duration_ms"),
                            "stderr_snippet_len": int(pkg_out.get("stderr_snippet_len") or 0),
                            "exit_code": pkg_out.get("exit_code"),
                            "detector": pkg_out.get("detector"),
                        },
                    )
                else:
                    rawb = pkg_out.get("stdout_raw")
                    if not isinstance(rawb, (bytes, bytearray)):
                        rawb = b""
                    pm = str(pkg_out.get("package_manager") or "unknown")
                    stored, total_ok, dropped, truncated_storage = parse_tabular_package_lines(
                        bytes(rawb),
                        package_manager=pm,
                        max_rows_store=MAX_PKG_ROWS_STORE,
                        name_max=PKG_NAME_MAX,
                        ver_max=PKG_VER_MAX,
                        arch_max=PKG_ARCH_MAX,
                    )
                    if len(stored) > MAX_PKG_ROWS_STORE:
                        stored = stored[:MAX_PKG_ROWS_STORE]
                    truncated_read = bool(pkg_out.get("truncated_read"))
                    partial = bool(truncated_read or truncated_storage or dropped > 0)
                    st_res = "partial" if partial else "success"
                    norm_doc: dict[str, Any] = {
                        "package_manager": pm if pm in ("dpkg", "rpm") else "unknown",
                        "package_count": total_ok,
                        "packages": stored,
                        "partial": bool(partial),
                        "truncated": bool(truncated_read or truncated_storage),
                        "source": "credentialed_check",
                    }
                    met_doc = {
                        "duration_ms": pkg_out.get("duration_ms"),
                        "plugin_key": PKG_KEY,
                        "plugin_version": PKG_VER,
                        "stderr_snippet_len": int(pkg_out.get("stderr_snippet_len") or 0),
                        "exit_code": pkg_out.get("exit_code"),
                        "package_manager": pm,
                        "detector": pkg_out.get("detector"),
                        "bytes_stdout": len(rawb),
                        "parse_dropped": dropped,
                        "truncated_read": truncated_read,
                    }
                    ridp = _insert_result(conn, run_id, tid, aid, PKG_KEY, PKG_VER, st_res, norm_doc, met_doc)
                    _insert_stdout_artifact(conn, ridp, bytes(rawb))
                    digest_summary = hashlib.sha256(
                        json.dumps(stored[:50], separators=(",", ":"), ensure_ascii=False).encode("utf-8", errors="replace")
                    ).hexdigest()[:24]
                    norm_obs = f"{norm_doc['package_manager']}:{total_ok}:{digest_summary}"
                    raw_obs = json.dumps(
                        {
                            "package_manager": norm_doc["package_manager"],
                            "package_count": total_ok,
                            "truncated": norm_doc["truncated"],
                            "partial": norm_doc["partial"],
                            "result_id": ridp,
                            "run_id": run_id,
                        },
                        separators=(",", ":"),
                        ensure_ascii=False,
                    )[:3500]
                    refp = f"run:{run_id}:target:{tid}:{PKG_KEY}@{PKG_VER}"
                    provp = {
                        "plugin_key": PKG_KEY,
                        "plugin_version": PKG_VER,
                        "run_id": run_id,
                        "target_row_id": tid,
                        "result_id": ridp,
                    }
                    if recon.upsert_cred_package_inventory_summary_observation(
                        conn,
                        asset_id=aid,
                        raw_value=raw_obs,
                        normalized_value=norm_obs[:500],
                        source_object_ref=refp,
                        provenance=provp,
                    ):
                        audit(
                            conn,
                            "credential_check.observation_written",
                            {"run_id": run_id, "target_row_id": tid, "asset_id": aid, "observation_type": "package_inventory_observed"},
                        )
                    counts["package_inventory_ok"] += 1

        if cancel_requested():
            conn.execute(
                """UPDATE credential_check_run_targets SET status = 'skipped', error_code = 'user_cancelled',
                    error_message_safe = 'cancelled', finished_at = datetime('now') WHERE id = ? AND status = 'running'""",
                (tid,),
            )
            counts["targets_skipped"] += 1
            conn.commit()
            audit(conn, "credential_check.target_completed", {"run_id": run_id, "target_row_id": tid, "outcome": "cancelled"})
            continue

        # ---- snmpv3.device_identity ----
        if can_snmp and want_snmp:
            counts["snmp_identity_attempted"] += 1
            snmp_out = collect_snmp_device_identity(
                host=host,
                port=port_snmp,
                principal=principal,
                secret=secret_obj,
                timeout_sec=op_to_snmp,
            )
            if not snmp_out.get("ok"):
                code = str(snmp_out.get("code") or "protocol_error")
                if code not in (
                    "auth_failed",
                    "timeout",
                    "network_unreachable",
                    "protocol_error",
                    "invalid_profile",
                    "dependency_missing",
                ):
                    code = "protocol_error"
                _insert_result(
                    conn,
                    run_id,
                    tid,
                    aid,
                    SNMP_KEY,
                    SNMP_VER,
                    "failed",
                    {"source": "credentialed_check", "error_code": code},
                    {
                        "plugin_key": SNMP_KEY,
                        "plugin_version": SNMP_VER,
                        "duration_ms": snmp_out.get("duration_ms"),
                    },
                )
            else:
                sd_raw = snmp_out.get("sys_descr")
                so_raw = snmp_out.get("sys_object_id")
                sn_raw = snmp_out.get("sys_name")
                sd_s = sd_raw if isinstance(sd_raw, str) else ""
                so_s = so_raw if isinstance(so_raw, str) else ""
                sn_s = sn_raw if isinstance(sn_raw, str) else ""
                st_label, partial_flag = classify_identity_partial(sd_raw, so_raw, sn_raw)
                id_block = {
                    "sys_descr": sd_s,
                    "sys_object_id": so_s,
                    "sys_name": sn_s,
                }
                ni = build_normalized_identity(sd_s, so_s, sn_s)
                met_snmp: dict[str, Any] = {
                    "duration_ms": snmp_out.get("duration_ms"),
                    "plugin_key": SNMP_KEY,
                    "plugin_version": SNMP_VER,
                    "oids_present": sum(1 for x in (sd_raw, so_raw, sn_raw) if x),
                }
                if st_label == "failed":
                    _insert_result(
                        conn,
                        run_id,
                        tid,
                        aid,
                        SNMP_KEY,
                        SNMP_VER,
                        "failed",
                        {
                            "source": "credentialed_check",
                            "error_code": "partial_result",
                            "snmpv3_identity": id_block,
                            "normalized_identity": ni,
                            "partial": True,
                        },
                        met_snmp,
                    )
                else:
                    norm_snmp: dict[str, Any] = {
                        "snmpv3_identity": id_block,
                        "normalized_identity": ni,
                        "source": "credentialed_check",
                        "partial": bool(partial_flag),
                    }
                    rids = _insert_result(conn, run_id, tid, aid, SNMP_KEY, SNMP_VER, st_label, norm_snmp, met_snmp)
                    art_doc = {
                        "sys_descr": id_block["sys_descr"][:2048],
                        "sys_object_id": id_block["sys_object_id"][:256],
                        "sys_name": id_block["sys_name"][:256],
                    }
                    _insert_snmp_identity_json_artifact(conn, rids, art_doc)
                    ref_snmp = f"run:{run_id}:target:{tid}:{SNMP_KEY}@{SNMP_VER}"
                    prov_snmp = {
                        "plugin_key": SNMP_KEY,
                        "plugin_version": SNMP_VER,
                        "run_id": run_id,
                        "target_row_id": tid,
                        "result_id": rids,
                    }
                    if sn_s.strip():
                        if recon.upsert_cred_snmp_sysname_observations(
                            conn,
                            asset_id=aid,
                            sys_name=sn_s,
                            run_id=run_id,
                            target_row_id=tid,
                            plugin_key=SNMP_KEY,
                            plugin_version=SNMP_VER,
                            result_id=rids,
                        ):
                            audit(
                                conn,
                                "credential_check.observation_written",
                                {"run_id": run_id, "target_row_id": tid, "asset_id": aid, "observation_type": "hostname_observed"},
                            )
                    digest_id = hashlib.sha256(
                        json.dumps(
                            [so_s, sn_s, ni.get("vendor_hint", ""), ni.get("model_hint", "")],
                            separators=(",", ":"),
                            ensure_ascii=False,
                        ).encode("utf-8", errors="replace")
                    ).hexdigest()[:28]
                    norm_id_obs = f"{digest_id}:{ni.get('vendor_hint', 'unknown')}"[:500]
                    raw_id_obs = json.dumps(
                        {
                            "sys_object_id": so_s[:256],
                            "sys_name": sn_s[:256],
                            "vendor_hint": ni.get("vendor_hint"),
                            "partial": bool(partial_flag),
                            "result_id": rids,
                            "run_id": run_id,
                        },
                        separators=(",", ":"),
                        ensure_ascii=False,
                    )[:3500]
                    if recon.upsert_cred_device_identity_summary_observation(
                        conn,
                        asset_id=aid,
                        normalized_digest=norm_id_obs,
                        raw_summary_json=raw_id_obs,
                        source_object_ref=ref_snmp,
                        provenance=prov_snmp,
                    ):
                        audit(
                            conn,
                            "credential_check.observation_written",
                            {"run_id": run_id, "target_row_id": tid, "asset_id": aid, "observation_type": "device_identity_observed"},
                        )
                    counts["snmp_identity_ok"] += 1

        conn.execute(
            """UPDATE credential_check_run_targets SET status = 'completed', error_code = NULL, error_message_safe = NULL,
                finished_at = datetime('now') WHERE id = ?""",
            (tid,),
        )
        counts["targets_completed"] += 1
        conn.commit()
        audit(
            conn,
            "credential_check.target_completed",
            {"run_id": run_id, "target_row_id": tid, "asset_id": aid, "outcome": "completed"},
        )

    counts["executor"] = "credential_check_worker"
    counts["slice"] = 9
    counts["job_id"] = job_id
    counts["credential_profile_id"] = profile_id
    return counts
