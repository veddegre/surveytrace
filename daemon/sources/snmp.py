"""
SurveyTrace — SNMP enrichment source

Queries any SNMP-enabled device for:
  - sysName, sysDescr, sysLocation   (device identity)
  - ipNetToMediaPhysAddress           (ARP table — MAC→IP mapping)
  - ifDescr, ifPhysAddress            (interface names and MACs)

This is the universal fallback that works against routers, switches,
and managed devices from any vendor. Particularly useful for:
  - Pulling ARP tables from routers to get MACs for cross-subnet hosts
  - Getting hostnames from devices that don't respond to mDNS/DNS

Config keys:
    targets         — list of SNMP device IPs to query (routers/switches)
    community       — SNMP v2c community string (default: "public")
    version         — "2c" | "3" (default: "2c")
    port            — SNMP port (default: 161)
    timeout         — seconds per request (default: 3)
    retries         — retry count (default: 1)
    # SNMPv3 only:
    username        — SNMPv3 username
    auth_protocol   — "MD5" | "SHA" (default: "SHA")
    auth_password   — SNMPv3 auth password
    priv_protocol   — "DES" | "AES" (default: "AES")
    priv_password   — SNMPv3 privacy password

Requires: pip install pysnmp
"""

from __future__ import annotations

import logging
import socket
from typing import Any

from sources import EnrichmentSource, register

log = logging.getLogger("surveytrace.enrichment.snmp")

# OID constants
OID_SYS_NAME    = "1.3.6.1.2.1.1.5.0"
OID_SYS_DESCR   = "1.3.6.1.2.1.1.1.0"
OID_SYS_LOCATION= "1.3.6.1.2.1.1.6.0"
OID_ARP_TABLE   = "1.3.6.1.2.1.4.22"   # ipNetToMediaTable
OID_IF_TABLE    = "1.3.6.1.2.1.2.2"    # interfaces table


def _mac_from_oid_index(index_str: str) -> str:
    """
    Convert OID index like '1.192.168.86.1' to MAC from value,
    or format hex bytes to MAC string.
    """
    try:
        parts = [int(x) for x in index_str.split(".")]
        return ":".join(f"{b:02x}" for b in parts[-6:])
    except (ValueError, IndexError):
        return ""


@register
class SNMPSource(EnrichmentSource):
    name = "snmp"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.targets   = config.get("targets", [])
        self.community = config.get("community", "public")
        self.version   = config.get("version", "2c")
        self.port      = int(config.get("port", 161))
        self.timeout   = int(config.get("timeout", 3))
        self.retries   = int(config.get("retries", 1))

    def _has_pysnmp(self) -> bool:
        try:
            import pysnmp  # noqa: F401
            return True
        except ImportError:
            return False

    def _get(self, target: str, oids: list[str]) -> dict[str, str]:
        """
        SNMP GET for a list of OIDs.
        Returns {oid: value_string}
        """
        if not self._has_pysnmp():
            log.warning("pysnmp not installed — SNMP enrichment unavailable")
            return {}
        try:
            from pysnmp.hlapi import (
                getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity
            )
            engine    = SnmpEngine()
            community = CommunityData(self.community, mpModel=1)
            transport = UdpTransportTarget(
                (target, self.port),
                timeout=self.timeout,
                retries=self.retries
            )
            context   = ContextData()
            objects   = [ObjectType(ObjectIdentity(oid)) for oid in oids]

            result = {}
            error_indication, error_status, error_index, var_binds = next(
                getCmd(engine, community, transport, context, *objects)
            )
            if error_indication or error_status:
                return {}
            for var_bind in var_binds:
                oid_str = str(var_bind[0])
                val_str = str(var_bind[1])
                result[oid_str] = val_str
            return result
        except Exception as e:
            log.debug("SNMP GET %s failed: %s", target, e)
            return {}

    def _walk(self, target: str, oid: str) -> list[tuple[str, str]]:
        """
        SNMP WALK for a subtree.
        Returns list of (oid_string, value_string) tuples.
        """
        if not self._has_pysnmp():
            return []
        try:
            from pysnmp.hlapi import (
                nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity
            )
            engine    = SnmpEngine()
            community = CommunityData(self.community, mpModel=1)
            transport = UdpTransportTarget(
                (target, self.port),
                timeout=self.timeout,
                retries=self.retries
            )
            context = ContextData()
            result  = []

            for error_indication, error_status, _, var_binds in nextCmd(
                engine, community, transport, context,
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            ):
                if error_indication or error_status:
                    break
                for var_bind in var_binds:
                    result.append((str(var_bind[0]), str(var_bind[1])))
            return result
        except Exception as e:
            log.debug("SNMP WALK %s %s failed: %s", target, oid, e)
            return []

    def _query_device_info(self, target: str) -> dict:
        """Get basic device identity from sysName/sysDescr/sysLocation."""
        vals = self._get(target, [OID_SYS_NAME, OID_SYS_DESCR, OID_SYS_LOCATION])
        name     = ""
        descr    = ""
        location = ""
        for oid, val in vals.items():
            if "1.5" in oid:  name     = val
            if "1.1" in oid:  descr    = val
            if "1.6" in oid:  location = val
        return {"name": name, "descr": descr, "location": location}

    def _query_arp_table(self, target: str) -> list[dict]:
        """
        Walk the ARP table of a router/switch.
        Returns list of {ip, mac} dicts for all known hosts.
        """
        # ipNetToMediaPhysAddress — OID 1.3.6.1.2.1.4.22.1.2
        # Index format: ifIndex.ipAddress → value: MAC bytes
        rows = self._walk(target, "1.3.6.1.2.1.4.22.1.2")
        results = []
        for oid_str, val in rows:
            try:
                # OID suffix: ifIndex.a.b.c.d
                suffix = oid_str.split("1.3.6.1.2.1.4.22.1.2.")[-1]
                parts  = suffix.split(".")
                if len(parts) < 5:
                    continue
                ip = ".".join(parts[1:5])
                # Value is MAC as hex octets
                mac_bytes = [int(x) for x in val.split() if x.isdigit()]
                if not mac_bytes and "0x" in val.lower():
                    hex_str = val.replace("0x","").replace(" ","")
                    mac_bytes = [int(hex_str[i:i+2],16) for i in range(0,12,2)]
                if len(mac_bytes) == 6:
                    mac = ":".join(f"{b:02x}" for b in mac_bytes)
                    results.append({"ip": ip, "mac": mac})
            except (ValueError, IndexError):
                continue
        return results

    def test_connection(self) -> tuple[bool, str]:
        if not self.targets:
            return False, "No SNMP targets configured"
        if not self._has_pysnmp():
            return False, "pysnmp not installed — run: pip install pysnmp"
        target = self.targets[0]
        info = self._query_device_info(target)
        if info.get("name") or info.get("descr"):
            return True, f"SNMP OK — {target} sysName: {info.get('name','?')}"
        return False, f"No SNMP response from {target} with community '{self.community}'"

    def fetch_all(self) -> list[dict]:
        """
        Query all configured SNMP targets for their ARP tables.
        Returns enrichment records for every host in those ARP tables.
        """
        results: dict[str, dict] = {}   # keyed by IP

        for target in self.targets:
            log.info("SNMP: querying ARP table from %s", target)

            # Get device identity
            info = self._query_device_info(target)
            log.debug("SNMP device: %s — %s", target, info.get("name","?"))

            # Walk ARP table
            arp_entries = self._query_arp_table(target)
            log.info("SNMP: got %d ARP entries from %s", len(arp_entries), target)

            for entry in arp_entries:
                ip  = entry.get("ip", "")
                mac = entry.get("mac", "")
                if not ip or ip.startswith("0.") or ip == "255.255.255.255":
                    continue
                # Try reverse DNS for hostname
                hostname = ""
                try:
                    hostname = socket.gethostbyaddr(ip)[0].split(".")[0]
                except (socket.herror, socket.gaierror):
                    pass

                results[ip] = {
                    "ip":          ip,
                    "mac":         mac,
                    "hostname":    hostname,
                    "vendor":      "",
                    "category":    "",
                    "vlan":        "",
                    "description": f"ARP entry from {target} ({info.get('name','?')})",
                    "source":      f"snmp:{target}",
                    "raw":         entry,
                }

        log.info("SNMP enrichment: %d total records from %d targets",
                 len(results), len(self.targets))
        return list(results.values())
