#!/usr/bin/env python3
"""
SurveyTrace — stdin JSON → transport handshake → stdout JSON (one line).

Invoked by PHP (api/lib_credential_profile_transport_test.php). Secrets on stdin only;
do not log payload. Stderr should remain empty on success.
"""

from __future__ import annotations

import json
import sys


def _emit(obj: dict) -> None:
    print(json.dumps(obj, separators=(",", ":")))


def main() -> int:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            _emit(
                {
                    "ok": False,
                    "code": "invalid_profile",
                    "transport": "",
                    "duration_ms": 0,
                    "runner_error": "empty_stdin",
                }
            )
            return 0
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as e:
            _emit(
                {
                    "ok": False,
                    "code": "protocol_error",
                    "transport": "",
                    "duration_ms": 0,
                    "runner_error": "stdin_json: " + str(e)[:200],
                }
            )
            return 0
        if not isinstance(payload, dict):
            _emit(
                {
                    "ok": False,
                    "code": "invalid_profile",
                    "transport": "",
                    "duration_ms": 0,
                    "runner_error": "payload_not_object",
                }
            )
            return 0
        transport = str(payload.get("transport") or "").lower().strip()
        if transport == "ssh":
            from cred_transport_ssh import run_test as run_ssh

            out = run_ssh(payload)
        elif transport in ("snmpv3", "snmp", "snmp3"):
            payload["transport"] = "snmpv3"
            from cred_transport_snmp import run_test as run_snmp

            out = run_snmp(payload)
        elif transport == "winrm":
            out = {
                "ok": False,
                "code": "unsupported_transport",
                "transport": "winrm",
                "duration_ms": 0,
            }
        else:
            out = {
                "ok": False,
                "code": "unsupported_transport",
                "transport": transport or "unknown",
                "duration_ms": 0,
            }
        _emit(out)
        return 0
    except Exception as e:
        # Never echo raw secret material; type + short message only.
        _emit(
            {
                "ok": False,
                "code": "runner_error",
                "transport": "",
                "duration_ms": 0,
                "runner_error": (type(e).__name__ + ": " + str(e))[:400],
            }
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
