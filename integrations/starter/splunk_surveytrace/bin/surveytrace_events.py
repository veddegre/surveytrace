#!/usr/bin/env python3
"""
SurveyTrace scripted input: pull JSONL reporting events and print to stdout for Splunk.

Configuration: ``<app>/local/surveytrace_pull.ini`` (see ``default/surveytrace_pull.ini.example``).
Uses Authorization: Bearer only (no token query string). Stdlib only.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from configparser import ConfigParser
from datetime import datetime, timedelta, timezone
from pathlib import Path


def app_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_config() -> tuple[str, str, int, Path]:
    ini = app_root() / "local" / "surveytrace_pull.ini"
    if not ini.is_file():
        print(
            "surveytrace_events: missing "
            + str(ini)
            + " — copy default/surveytrace_pull.ini.example to local/surveytrace_pull.ini",
            file=sys.stderr,
        )
        sys.exit(1)
    cp = ConfigParser()
    cp.read(ini, encoding="utf-8")
    if not cp.has_section("pull"):
        print("surveytrace_events: [pull] section missing", file=sys.stderr)
        sys.exit(1)
    base = (cp.get("pull", "base_url", fallback="") or "").strip().rstrip("/")
    token = (cp.get("pull", "bearer_token", fallback="") or "").strip()
    if base == "" or token == "":
        print("surveytrace_events: base_url and bearer_token required in [pull]", file=sys.stderr)
        sys.exit(1)
    lookback = int(cp.get("pull", "initial_lookback_hours", fallback="24"))
    splunk_home = os.environ.get("SPLUNK_HOME", "").strip()
    cdir_raw = (cp.get("pull", "checkpoint_dir", fallback="") or "").strip()
    if cdir_raw:
        checkpoint_dir = Path(cdir_raw)
    elif splunk_home:
        checkpoint_dir = (
            Path(splunk_home) / "var" / "lib" / "splunk" / "modinputs" / "surveytrace"
        )
    else:
        checkpoint_dir = app_root() / "var" / "state" / "surveytrace"
    return base, token, max(1, lookback), checkpoint_dir


def checkpoint_path(checkpoint_dir: Path) -> Path:
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    return checkpoint_dir / "last_since.txt"


def read_since(cp_path: Path, lookback_h: int) -> str:
    if cp_path.is_file():
        raw = cp_path.read_text(encoding="utf-8").strip()
        if raw:
            return raw
    since = datetime.now(timezone.utc) - timedelta(hours=lookback_h)
    return since.strftime("%Y-%m-%dT%H:%M:%SZ")


def write_since(cp_path: Path, iso: str) -> None:
    if not iso:
        return
    tmp = cp_path.with_suffix(".tmp")
    tmp.write_text(iso + "\n", encoding="utf-8")
    tmp.replace(cp_path)


def redact(msg: str, token: str) -> str:
    out = msg
    if token:
        out = out.replace(token, "[REDACTED]")
    return out


def max_occurred_from_jsonl(body: str) -> str | None:
    best: str | None = None
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        oc = obj.get("occurred_at")
        if not isinstance(oc, str) or not oc:
            continue
        if best is None or oc > best:
            best = oc
    return best


def bump_since_exclusive(iso: str) -> str:
    """API uses inclusive ``since``; advance checkpoint slightly to limit duplicates."""
    try:
        if iso.endswith("Z") and len(iso) >= 20:
            dt = datetime.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        else:
            dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return iso
    nxt = dt + timedelta(seconds=1)
    return nxt.strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> None:
    base, token, lookback_h, checkpoint_dir = load_config()
    cp_path = checkpoint_path(checkpoint_dir)
    since = read_since(cp_path, lookback_h)

    q = urllib.parse.urlencode({"since": since, "format": "jsonl"})
    path = "/api/integrations_events.php?" + q
    url = base + path

    req = urllib.request.Request(
        url,
        headers={"Authorization": "Bearer " + token},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            raw = resp.read().decode(charset, errors="replace")
    except urllib.error.HTTPError as e:
        msg = "surveytrace_events: HTTP " + str(e.code)
        if e.reason:
            msg += " " + str(e.reason)
        print(redact(msg, token), file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        print("surveytrace_events: " + redact(str(reason), token), file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print("surveytrace_events: " + redact(str(e), token), file=sys.stderr)
        sys.exit(1)

    if raw.strip():
        sys.stdout.write(raw)
        if not raw.endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.flush()

    max_oc = max_occurred_from_jsonl(raw)
    if max_oc:
        write_since(cp_path, bump_since_exclusive(max_oc))
    elif raw.strip():
        write_since(cp_path, bump_since_exclusive(since))


if __name__ == "__main__":
    main()
