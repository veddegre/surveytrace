"""
SurveyTrace — DHCP lease enrichment source

Generic DHCP importer for common lease formats:
  - dnsmasq/odhcpd: "<expiry> <mac> <ip> <hostname> <client_id>"
  - ISC dhcpd.leases blocks
  - JSON list/object exports

Config keys:
    paths         — comma-separated lease file paths
    format        — "auto" | "dnsmasq" | "isc" | "json" (default: "auto")
    include_expired — bool-like ("0"/"1"/"true"/"false"), default: false
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

log = logging.getLogger("surveytrace.enrichment.dhcp")


def _truthy(val: Any, default: bool = False) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _norm_mac(mac: str) -> str:
    m = re.sub(r"[^0-9a-fA-F]", "", (mac or ""))
    if len(m) != 12:
        return ""
    return ":".join(m[i:i + 2] for i in range(0, 12, 2)).lower()


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


@register
class DHCPLeasesSource(EnrichmentSource):
    name = "dhcp_leases"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        raw_paths = str(config.get("paths", "") or "")
        self.paths = [p.strip() for p in raw_paths.split(",") if p.strip()]
        self.fmt = str(config.get("format", "auto") or "auto").strip().lower()
        self.include_expired = _truthy(config.get("include_expired", False), False)

    def test_connection(self) -> tuple[bool, str]:
        if not self.paths:
            return False, "No lease file paths configured"
        existing = [p for p in self.paths if Path(p).exists()]
        if not existing:
            return False, "No configured lease files are readable on this host"
        return True, f"Found {len(existing)} lease file(s)"

    def _parse_dnsmasq(self, content: str, source_path: str) -> list[dict]:
        out: list[dict] = []
        now = int(time.time())
        for line in content.splitlines():
            row = line.strip()
            if not row or row.startswith("#"):
                continue
            parts = row.split()
            if len(parts) < 4:
                continue
            try:
                expiry = int(parts[0])
            except ValueError:
                continue
            mac = _norm_mac(parts[1])
            ip = parts[2].strip()
            hostname = "" if parts[3] == "*" else parts[3].strip()
            if not mac or not _valid_ip(ip):
                continue
            if not self.include_expired and expiry != 0 and expiry < now:
                continue
            out.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": "",
                "category": "",
                "vlan": "",
                "description": f"DHCP lease ({source_path})",
                "source": "dhcp_lease",
                "raw": {"expiry": expiry, "path": source_path},
            })
        return out

    def _parse_isc(self, content: str, source_path: str) -> list[dict]:
        out: list[dict] = []
        now = int(time.time())
        for m in re.finditer(r"lease\s+([0-9.]+)\s+\{(.*?)\}", content, flags=re.S):
            ip = m.group(1).strip()
            block = m.group(2)
            if not _valid_ip(ip):
                continue

            mac = ""
            hm = re.search(r"hardware\s+ethernet\s+([0-9a-fA-F:.-]+)\s*;", block)
            if hm:
                mac = _norm_mac(hm.group(1))
            if not mac:
                continue

            hostname = ""
            hh = re.search(r'client-hostname\s+"([^"]+)"\s*;', block)
            if hh:
                hostname = hh.group(1).strip()

            expired = False
            ends = re.search(r"ends\s+\d+\s+(\d{4})/(\d{2})/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})\s*;", block)
            if ends:
                try:
                    y, mo, d, h, mi, s = [int(ends.group(i)) for i in range(1, 7)]
                    exp = int(time.mktime((y, mo, d, h, mi, s, 0, 0, -1)))
                    expired = exp < now
                except ValueError:
                    expired = False
            if not self.include_expired and expired:
                continue

            out.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": "",
                "category": "",
                "vlan": "",
                "description": f"DHCP lease ({source_path})",
                "source": "dhcp_lease",
                "raw": {"path": source_path},
            })
        return out

    def _parse_json(self, content: str, source_path: str) -> list[dict]:
        out: list[dict] = []
        payload = json.loads(content)
        rows: list[dict[str, Any]]
        if isinstance(payload, list):
            rows = [r for r in payload if isinstance(r, dict)]
        elif isinstance(payload, dict):
            if isinstance(payload.get("leases"), list):
                rows = [r for r in payload["leases"] if isinstance(r, dict)]
            elif isinstance(payload.get("data"), list):
                rows = [r for r in payload["data"] if isinstance(r, dict)]
            else:
                rows = [payload]
        else:
            rows = []

        for row in rows:
            ip = str(row.get("ip") or row.get("ipaddr") or row.get("address") or "").strip()
            mac = _norm_mac(str(row.get("mac") or row.get("macaddr") or row.get("hwaddr") or ""))
            if not ip or not mac or not _valid_ip(ip):
                continue
            hostname = str(row.get("hostname") or row.get("host") or row.get("name") or "").strip()
            out.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": "",
                "category": "",
                "vlan": "",
                "description": f"DHCP lease ({source_path})",
                "source": "dhcp_lease",
                "raw": row,
            })
        return out

    def _detect_format(self, content: str) -> str:
        c = content.lstrip()
        if c.startswith("[") or c.startswith("{"):
            return "json"
        if re.search(r"\blease\s+[0-9.]+\s+\{", content):
            return "isc"
        return "dnsmasq"

    def fetch_all(self) -> list[dict]:
        by_ip: dict[str, dict] = {}
        for path in self.paths:
            p = Path(path)
            if not p.exists():
                log.debug("DHCP source path not found: %s", path)
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                log.warning("DHCP source read failed (%s): %s", path, e)
                continue

            fmt = self.fmt if self.fmt in {"dnsmasq", "isc", "json"} else self._detect_format(content)
            try:
                if fmt == "isc":
                    rows = self._parse_isc(content, path)
                elif fmt == "json":
                    rows = self._parse_json(content, path)
                else:
                    rows = self._parse_dnsmasq(content, path)
            except Exception as e:
                log.warning("DHCP parse failed (%s as %s): %s", path, fmt, e)
                continue

            for rec in rows:
                ip = rec.get("ip", "")
                if ip:
                    by_ip[ip] = rec

        out = list(by_ip.values())
        log.info("DHCP lease enrichment: %d total records", len(out))
        return out
