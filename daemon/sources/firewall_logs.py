"""
SurveyTrace — Firewall log enrichment source.

Parser modes:
  - auto
  - kv        (key=value logs; pfSense/OPNsense/syslog style)
  - jsonl
  - json

Config keys:
    paths           — comma-separated firewall log file paths
    parser          — mode above (default: auto)
    direction       — any|in|out (default: any)
    include_blocked — bool-like, include blocked/denied drops (default: true)
    max_age_hours   — record age window (default: 168, set 0 to disable)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from sources import EnrichmentSource, register

log = logging.getLogger("surveytrace.enrichment.firewall_logs")


def _truthy(val: Any, default: bool = False) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _norm_mac(val: str) -> str:
    s = re.sub(r"[^0-9a-fA-F]", "", (val or ""))
    if len(s) != 12:
        return ""
    return ":".join(s[i:i + 2] for i in range(0, 12, 2)).lower()


@register
class FirewallLogsSource(EnrichmentSource):
    name = "firewall_logs"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.paths = [p.strip() for p in str(config.get("paths", "") or "").split(",") if p.strip()]
        self.parser = str(config.get("parser", "auto") or "auto").strip().lower()
        self.direction = str(config.get("direction", "any") or "any").strip().lower()
        self.include_blocked = _truthy(config.get("include_blocked", True), True)
        self.max_age_hours = int(str(config.get("max_age_hours", "168") or "168"))
        self.cutoff_ts = int(time.time()) - (self.max_age_hours * 3600) if self.max_age_hours > 0 else 0

    def test_connection(self) -> tuple[bool, str]:
        if not self.paths:
            return False, "No firewall log paths configured"
        existing = [p for p in self.paths if Path(p).exists()]
        if not existing:
            return False, "No configured firewall log files are readable on this host"
        return True, f"Found {len(existing)} firewall log file(s)"

    def _allow_action(self, action: str) -> bool:
        a = (action or "").strip().lower()
        if self.include_blocked:
            return True
        return a not in {"block", "blocked", "deny", "denied", "drop", "dropped", "reject"}

    def _allow_direction(self, direction: str) -> bool:
        if self.direction == "any":
            return True
        d = (direction or "").strip().lower()
        if self.direction == "in":
            return d in {"in", "ingress", "inbound"}
        if self.direction == "out":
            return d in {"out", "egress", "outbound"}
        return True

    def _mk(self, ip: str, mac: str, hostname: str, parser_name: str, source_path: str, raw: dict[str, Any]) -> dict | None:
        if not _valid_ip(ip):
            return None
        return {
            "ip": ip,
            "mac": _norm_mac(mac),
            "hostname": (hostname or "").strip(),
            "vendor": "",
            "category": "",
            "vlan": "",
            "description": f"Firewall log ({parser_name}, {source_path})",
            "source": "firewall_log",
            "raw": raw,
        }

    def _parse_kv(self, content: str, source_path: str) -> list[dict]:
        out: list[dict] = []
        kv_re = re.compile(r"([A-Za-z0-9_.-]+)=([^\s]+)")
        for line in content.splitlines():
            if "=" not in line:
                continue
            row = {k.lower(): v.strip().strip('"') for k, v in kv_re.findall(line)}
            action = row.get("action") or row.get("act") or row.get("disposition") or ""
            direction = row.get("dir") or row.get("direction") or row.get("flowdir") or ""
            if not self._allow_action(action) or not self._allow_direction(direction):
                continue

            ip = (
                row.get("src")
                or row.get("src_ip")
                or row.get("source")
                or row.get("client_ip")
                or row.get("ip")
                or ""
            )
            mac = row.get("src_mac") or row.get("mac") or row.get("srcmac") or ""
            hostname = row.get("host") or row.get("hostname") or row.get("src_host") or ""
            rec = self._mk(ip, mac, hostname, "kv", source_path, {"line": line[:400], "fields": row})
            if rec:
                out.append(rec)
        return out

    def _parse_json_records(self, rows: list[dict[str, Any]], source_path: str, parser_name: str) -> list[dict]:
        out: list[dict] = []
        now = int(time.time())
        for row in rows:
            action = str(row.get("action") or row.get("act") or row.get("disposition") or "")
            direction = str(row.get("direction") or row.get("dir") or row.get("flowdir") or "")
            if not self._allow_action(action) or not self._allow_direction(direction):
                continue

            ts = row.get("ts") or row.get("timestamp") or row.get("time")
            if self.cutoff_ts and ts is not None:
                try:
                    ts_int = int(float(ts))
                    if ts_int > now + 86400:
                        ts_int = 0
                    if ts_int and ts_int < self.cutoff_ts:
                        continue
                except (ValueError, TypeError):
                    pass

            ip = str(
                row.get("src_ip")
                or row.get("src")
                or row.get("source")
                or row.get("client_ip")
                or row.get("ip")
                or ""
            ).strip()
            mac = str(row.get("src_mac") or row.get("mac") or row.get("srcmac") or "").strip()
            hostname = str(row.get("hostname") or row.get("host") or row.get("src_host") or "").strip()
            rec = self._mk(ip, mac, hostname, parser_name, source_path, row)
            if rec:
                out.append(rec)
        return out

    def _parse_jsonl(self, content: str, source_path: str) -> list[dict]:
        rows: list[dict[str, Any]] = []
        for line in content.splitlines():
            s = line.strip()
            if not s.startswith("{"):
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
        return self._parse_json_records(rows, source_path, "jsonl")

    def _parse_json(self, content: str, source_path: str) -> list[dict]:
        payload = json.loads(content)
        rows: list[dict[str, Any]] = []
        if isinstance(payload, list):
            rows = [x for x in payload if isinstance(x, dict)]
        elif isinstance(payload, dict):
            if isinstance(payload.get("records"), list):
                rows = [x for x in payload["records"] if isinstance(x, dict)]
            elif isinstance(payload.get("events"), list):
                rows = [x for x in payload["events"] if isinstance(x, dict)]
            else:
                rows = [payload]
        return self._parse_json_records(rows, source_path, "json")

    def _detect_parser(self, content: str) -> str:
        c = content.lstrip()
        if c.startswith("{") or c.startswith("["):
            return "json"
        if re.search(r"^\s*\{", content, re.M):
            return "jsonl"
        if "=" in content:
            return "kv"
        return "kv"

    def fetch_all(self) -> list[dict]:
        by_ip: dict[str, dict] = {}
        for path in self.paths:
            p = Path(path)
            if not p.exists():
                log.debug("Firewall log path not found: %s", path)
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                log.warning("Firewall log read failed (%s): %s", path, e)
                continue
            parser = self.parser if self.parser in {"kv", "jsonl", "json"} else self._detect_parser(content)
            try:
                if parser == "jsonl":
                    rows = self._parse_jsonl(content, path)
                elif parser == "json":
                    rows = self._parse_json(content, path)
                else:
                    rows = self._parse_kv(content, path)
            except Exception as e:
                log.warning("Firewall log parse failed (%s as %s): %s", path, parser, e)
                continue
            for rec in rows:
                ip = rec.get("ip", "")
                if ip:
                    by_ip[ip] = rec
        out = list(by_ip.values())
        log.info("Firewall log enrichment: %d total records", len(out))
        return out
