"""
SurveyTrace — DNS log enrichment source.

Parser modes: auto, pihole, dnsmasq, bind, jsonl, json
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Callable

from sources import EnrichmentSource, register, resolve_jailed_path

log = logging.getLogger("surveytrace.enrichment.dns_logs")


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


def _looks_like_fqdn(name: str) -> bool:
    s = (name or "").strip().strip(".").lower()
    return "." in s and re.fullmatch(r"[a-z0-9._-]+", s) is not None


def _host_from_fqdn(name: str) -> str:
    s = (name or "").strip().strip(".")
    if not s or s.endswith(".in-addr.arpa") or s.endswith(".ip6.arpa"):
        return ""
    head = s.split(".", 1)[0]
    return head if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", head) else ""


@register
class DNSLogsSource(EnrichmentSource):
    name = "dns_logs"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.paths = [p.strip() for p in str(config.get("paths", "")).split(",") if p.strip()]
        self.parser = str(config.get("parser", "auto") or "auto").strip().lower()
        roots_raw = str(config.get("allowed_roots", "") or "")
        self.allowed_roots = [r.strip() for r in roots_raw.split(",") if r.strip()]
        self.allowed_suffixes = [
            s.strip().lower().lstrip(".")
            for s in str(config.get("allowed_suffixes", "")).split(",")
            if s.strip()
        ]
        self.include_reverse = _truthy(config.get("include_reverse", False), False)
        self.max_age_hours = int(str(config.get("max_age_hours", "168") or "168"))
        self.cutoff_ts = int(time.time()) - (self.max_age_hours * 3600) if self.max_age_hours > 0 else 0

    def test_connection(self) -> tuple[bool, str]:
        if not self.paths:
            return False, "No DNS log file paths configured"
        exists = [p for p in self.paths if resolve_jailed_path(p, self.allowed_roots) is not None]
        if not exists:
            return False, "No configured DNS log files are readable on this host (or path is outside allowed roots)"
        return True, f"Found {len(exists)} DNS log file(s)"

    def _domain_allowed(self, name: str) -> bool:
        if not self.allowed_suffixes:
            return True
        s = name.strip(".").lower()
        return any(s == suf or s.endswith("." + suf) for suf in self.allowed_suffixes)

    def _mk(self, ip: str, fqdn: str, ts: int | None, parser_name: str, source_path: str, raw: dict[str, Any] | None = None) -> dict | None:
        if not _valid_ip(ip) or not _looks_like_fqdn(fqdn):
            return None
        if not self._domain_allowed(fqdn):
            return None
        if ts and self.cutoff_ts and ts < self.cutoff_ts:
            return None
        host = _host_from_fqdn(fqdn)
        if not host:
            return None
        rr = dict(raw or {})
        rr.update({"fqdn": fqdn, "path": source_path, "parser": parser_name})
        if ts:
            rr["ts"] = ts
        return {
            "ip": ip,
            "mac": "",
            "hostname": host,
            "vendor": "",
            "category": "",
            "vlan": "",
            "description": f"DNS log ({parser_name}, {source_path})",
            "source": "dns_log",
            "raw": rr,
        }

    def _parse_dnsmasq_like(self, content: str, source_path: str, parser_name: str) -> list[dict]:
        out: list[dict] = []
        patt = re.compile(r"\bquery\[[A-Z]+\]\s+(?P<name>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)", re.I)
        for line in content.splitlines():
            m = patt.search(line)
            if not m:
                continue
            name = m.group("name").strip().strip(".")
            if name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa"):
                if not self.include_reverse:
                    continue
                continue
            rec = self._mk(m.group("ip").strip(), name, None, parser_name, source_path, {"line": line[:240]})
            if rec:
                out.append(rec)
        return out

    def _parse_bind(self, content: str, source_path: str) -> list[dict]:
        out: list[dict] = []
        patt = re.compile(r"\bclient\b.*?\s(?P<ip>[0-9a-fA-F:.]+)#\d+\s+\((?P<name>[^)]+)\):\s+query:", re.I)
        for line in content.splitlines():
            m = patt.search(line)
            if not m:
                continue
            name = m.group("name").strip().strip(".")
            if name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa"):
                if not self.include_reverse:
                    continue
                continue
            rec = self._mk(m.group("ip").strip(), name, None, "bind", source_path, {"line": line[:240]})
            if rec:
                out.append(rec)
        return out

    def _parse_json_records(self, rows: list[dict], source_path: str, parser_name: str) -> list[dict]:
        out: list[dict] = []
        now = int(time.time())
        for r in rows:
            ip = str(r.get("client_ip") or r.get("ip") or r.get("src_ip") or "").strip()
            name = str(r.get("qname") or r.get("query") or r.get("name") or "").strip().strip(".")
            if name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa"):
                if not self.include_reverse:
                    continue
                continue
            ts_raw = r.get("ts") or r.get("timestamp") or r.get("time")
            ts = None
            if isinstance(ts_raw, (int, float)):
                ts = int(ts_raw)
            elif isinstance(ts_raw, str) and ts_raw.isdigit():
                ts = int(ts_raw)
            elif isinstance(ts_raw, str) and "T" in ts_raw:
                try:
                    ts = int(time.mktime(time.strptime(ts_raw[:19], "%Y-%m-%dT%H:%M:%S")))
                except ValueError:
                    ts = None
            if ts and ts > now + 86400:
                ts = None
            rec = self._mk(ip, name, ts, parser_name, source_path, r)
            if rec:
                out.append(rec)
        return out

    def _parse_jsonl(self, content: str, source_path: str) -> list[dict]:
        rows: list[dict] = []
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
        rows: list[dict] = []
        payload = json.loads(content)
        if isinstance(payload, list):
            rows = [x for x in payload if isinstance(x, dict)]
        elif isinstance(payload, dict):
            if isinstance(payload.get("records"), list):
                rows = [x for x in payload["records"] if isinstance(x, dict)]
            elif isinstance(payload.get("queries"), list):
                rows = [x for x in payload["queries"] if isinstance(x, dict)]
            else:
                rows = [payload]
        return self._parse_json_records(rows, source_path, "json")

    def _detect_parser(self, content: str) -> str:
        c = content.lstrip()
        if c.startswith("{") or c.startswith("["):
            return "json"
        if re.search(r"\bquery\[[A-Z]+\]\s+\S+\s+from\s+[0-9a-fA-F:.]+", content, re.I):
            return "dnsmasq"
        if re.search(r"\bclient\b.*?#\d+\s+\([^)]+\):\s+query:", content, re.I):
            return "bind"
        if re.search(r"^\s*\{", content, re.M):
            return "jsonl"
        return "dnsmasq"

    def fetch_all(self) -> list[dict]:
        by_ip: dict[str, dict] = {}
        parsers: dict[str, Callable[[str, str], list[dict]]] = {
            "pihole": lambda c, p: self._parse_dnsmasq_like(c, p, "pihole"),
            "dnsmasq": lambda c, p: self._parse_dnsmasq_like(c, p, "dnsmasq"),
            "bind": self._parse_bind,
            "jsonl": self._parse_jsonl,
            "json": self._parse_json,
        }
        for path in self.paths:
            p = resolve_jailed_path(path, self.allowed_roots)
            if p is None:
                log.debug("DNS log path not found: %s", path)
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                log.warning("DNS log read failed (%s): %s", path, e)
                continue
            parser = self.parser if self.parser in parsers else self._detect_parser(content)
            fn = parsers.get(parser, parsers["dnsmasq"])
            try:
                rows = fn(content, path)
            except Exception as e:
                log.warning("DNS log parse failed (%s as %s): %s", path, parser, e)
                continue
            for rec in rows:
                ip = rec.get("ip", "")
                if ip:
                    by_ip[ip] = rec
        out = list(by_ip.values())
        log.info("DNS log enrichment: %d total records", len(out))
        return out
