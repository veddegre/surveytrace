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
import re
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
OID_IF_DESCR    = "1.3.6.1.2.1.2.2.1.2"
OID_DOT1D_FDB_ADDR = "1.3.6.1.2.1.17.4.3.1.1"      # dot1dTpFdbAddress
OID_DOT1D_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"      # dot1dTpFdbPort
OID_DOT1D_BASEPORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePortIfIndex
OID_LLDP_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"      # lldpRemSysName
OID_LLDP_PORTDESC = "1.0.8802.1.1.2.1.4.1.1.8"     # lldpRemPortDesc
OID_LLDP_MGMT_ADDR = "1.0.8802.1.1.2.1.4.2.1.4"    # lldpRemManAddrTable index carries addr
OID_CDP_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6" # cdpCacheDeviceId
OID_CDP_DEVICE_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
OID_CDP_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"
OID_CDP_ADDRESS = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"   # cdpCacheAddress


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


def _clean_text(value: str) -> str:
    s = (value or "").strip()
    return re.sub(r"\s+", " ", s).strip()


def _parse_ip_from_numeric_suffix(oid_str: str, base_oid: str) -> str:
    """Parse IP from OID suffix where trailing bytes encode the address."""
    if not oid_str.startswith(base_oid + "."):
        return ""
    try:
        nums = [int(x) for x in oid_str[len(base_oid) + 1:].split(".") if x]
    except ValueError:
        return ""
    if len(nums) >= 6 and nums[-5] == 4:
        octets = nums[-4:]
        if all(0 <= o <= 255 for o in octets):
            return ".".join(str(o) for o in octets)
    return ""


def _parse_ip_from_value(value: str) -> str:
    """Parse SNMP OCTET STRING text forms into IPv4."""
    s = (value or "").strip()
    if not s:
        return ""
    if s.startswith("0x"):
        hex_str = re.sub(r"[^0-9a-fA-F]", "", s[2:])
        if len(hex_str) >= 8:
            try:
                octets = [int(hex_str[i:i+2], 16) for i in range(0, 8, 2)]
                if all(0 <= o <= 255 for o in octets):
                    return ".".join(str(o) for o in octets)
            except ValueError:
                pass
    nums = [int(x) for x in re.findall(r"\d+", s)]
    if len(nums) >= 4 and all(0 <= p <= 255 for p in nums[:4]):
        return ".".join(str(p) for p in nums[:4])
    return ""


def _parse_mac_from_value(value: str) -> str:
    """Parse SNMP value text into normalized MAC address when possible."""
    s = (value or "").strip()
    if not s:
        return ""
    if s.startswith("0x"):
        hex_str = re.sub(r"[^0-9a-fA-F]", "", s[2:])
        if len(hex_str) >= 12:
            hex_str = hex_str[:12]
            return ":".join(hex_str[i:i+2] for i in range(0, 12, 2)).lower()
    nums = [int(x) for x in re.findall(r"\d+", s)]
    if len(nums) >= 6 and all(0 <= n <= 255 for n in nums[:6]):
        return ":".join(f"{n:02x}" for n in nums[:6])
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

    def _query_lldp_neighbors(self, target: str) -> list[dict]:
        """Read LLDP remote neighbor info with management IP where available."""
        out: list[dict] = []
        sys_rows = self._walk(target, OID_LLDP_SYSNAME)
        port_rows = self._walk(target, OID_LLDP_PORTDESC)
        mgmt_rows = self._walk(target, OID_LLDP_MGMT_ADDR)
        if not (sys_rows or mgmt_rows):
            return out

        sys_by_key: dict[tuple[int, int, int], str] = {}
        port_by_key: dict[tuple[int, int, int], str] = {}
        ip_by_key: dict[tuple[int, int, int], str] = {}

        for oid_str, val in sys_rows:
            try:
                suffix = oid_str.split(OID_LLDP_SYSNAME + ".", 1)[1]
                a, b, c = [int(x) for x in suffix.split(".")[:3]]
                sys_by_key[(a, b, c)] = _clean_text(val)
            except Exception:
                continue
        for oid_str, val in port_rows:
            try:
                suffix = oid_str.split(OID_LLDP_PORTDESC + ".", 1)[1]
                a, b, c = [int(x) for x in suffix.split(".")[:3]]
                port_by_key[(a, b, c)] = _clean_text(val)
            except Exception:
                continue
        for oid_str, _ in mgmt_rows:
            try:
                suffix = oid_str.split(OID_LLDP_MGMT_ADDR + ".", 1)[1]
                nums = [int(x) for x in suffix.split(".")]
                if len(nums) < 8:
                    continue
                key = (nums[0], nums[1], nums[2])
                ip = _parse_ip_from_numeric_suffix(oid_str, OID_LLDP_MGMT_ADDR)
                if ip:
                    ip_by_key[key] = ip
            except Exception:
                continue

        for key, ip in ip_by_key.items():
            hostname = sys_by_key.get(key, "")
            portdesc = port_by_key.get(key, "")
            out.append({
                "ip": ip,
                "hostname": hostname.split(".")[0] if hostname else "",
                "description": f"LLDP neighbor via {target}" + (f" port {portdesc}" if portdesc else ""),
                "source": f"snmp_lldp:{target}",
                "raw": {"key": key, "sysname": hostname, "port": portdesc},
            })
        return out

    def _query_cdp_neighbors(self, target: str) -> list[dict]:
        """Read CDP neighbor cache and return management IP + identity hints."""
        out: list[dict] = []
        id_rows = self._walk(target, OID_CDP_DEVICE_ID)
        port_rows = self._walk(target, OID_CDP_DEVICE_PORT)
        plat_rows = self._walk(target, OID_CDP_PLATFORM)
        addr_rows = self._walk(target, OID_CDP_ADDRESS)
        if not (id_rows or addr_rows):
            return out

        def key_from_oid(oid: str, base: str) -> str:
            return oid.split(base + ".", 1)[1] if (base + ".") in oid else ""

        id_by_key: dict[str, str] = {}
        port_by_key: dict[str, str] = {}
        plat_by_key: dict[str, str] = {}
        ip_by_key: dict[str, str] = {}

        for oid_str, val in id_rows:
            k = key_from_oid(oid_str, OID_CDP_DEVICE_ID)
            if k:
                id_by_key[k] = _clean_text(val)
        for oid_str, val in port_rows:
            k = key_from_oid(oid_str, OID_CDP_DEVICE_PORT)
            if k:
                port_by_key[k] = _clean_text(val)
        for oid_str, val in plat_rows:
            k = key_from_oid(oid_str, OID_CDP_PLATFORM)
            if k:
                plat_by_key[k] = _clean_text(val)
        for oid_str, val in addr_rows:
            k = key_from_oid(oid_str, OID_CDP_ADDRESS)
            if not k:
                continue
            ip = _parse_ip_from_value(val)
            if ip:
                ip_by_key[k] = ip

        for key, ip in ip_by_key.items():
            dev_id = id_by_key.get(key, "")
            out.append({
                "ip": ip,
                "hostname": dev_id.split(".")[0] if dev_id else "",
                "vendor": plat_by_key.get(key, ""),
                "description": f"CDP neighbor via {target}" + (f" port {port_by_key.get(key,'')}" if port_by_key.get(key) else ""),
                "source": f"snmp_cdp:{target}",
                "raw": {"key": key, "device_id": dev_id, "platform": plat_by_key.get(key, "")},
            })
        return out

    def _query_switch_fdb(self, target: str, mac_to_ip: dict[str, str]) -> list[dict]:
        """
        Query BRIDGE-MIB forwarding database (FDB) and map MAC -> IP
        using ARP-correlated MACs where possible.
        """
        out: list[dict] = []
        fdb_addr_rows = self._walk(target, OID_DOT1D_FDB_ADDR)
        fdb_port_rows = self._walk(target, OID_DOT1D_FDB_PORT)
        baseport_rows = self._walk(target, OID_DOT1D_BASEPORT_IFINDEX)
        ifdescr_rows = self._walk(target, OID_IF_DESCR)
        if not (fdb_addr_rows and fdb_port_rows):
            return out

        mac_by_suffix: dict[str, str] = {}
        port_by_suffix: dict[str, str] = {}
        ifindex_by_baseport: dict[str, str] = {}
        ifdescr_by_ifindex: dict[str, str] = {}

        for oid_str, val in fdb_addr_rows:
            if (OID_DOT1D_FDB_ADDR + ".") not in oid_str:
                continue
            suffix = oid_str.split(OID_DOT1D_FDB_ADDR + ".", 1)[1]
            mac = _parse_mac_from_value(val)
            if not mac:
                # fallback: dot1d index is often the MAC bytes
                mac = _mac_from_oid_index(suffix)
            if mac:
                mac_by_suffix[suffix] = mac

        for oid_str, val in fdb_port_rows:
            if (OID_DOT1D_FDB_PORT + ".") not in oid_str:
                continue
            suffix = oid_str.split(OID_DOT1D_FDB_PORT + ".", 1)[1]
            port_by_suffix[suffix] = _clean_text(val)

        for oid_str, val in baseport_rows:
            if (OID_DOT1D_BASEPORT_IFINDEX + ".") not in oid_str:
                continue
            baseport = oid_str.split(OID_DOT1D_BASEPORT_IFINDEX + ".", 1)[1]
            ifindex_by_baseport[baseport] = _clean_text(val)

        for oid_str, val in ifdescr_rows:
            if (OID_IF_DESCR + ".") not in oid_str:
                continue
            ifindex = oid_str.split(OID_IF_DESCR + ".", 1)[1]
            ifdescr_by_ifindex[ifindex] = _clean_text(val)

        for suffix, mac in mac_by_suffix.items():
            ip = mac_to_ip.get(mac, "")
            if not ip:
                continue
            bridge_port = port_by_suffix.get(suffix, "")
            ifindex = ifindex_by_baseport.get(bridge_port, "")
            ifdescr = ifdescr_by_ifindex.get(ifindex, "")
            desc = f"Switch FDB entry via {target}"
            if ifdescr:
                desc += f" port {ifdescr}"
            elif bridge_port:
                desc += f" bridge-port {bridge_port}"
            out.append({
                "ip": ip,
                "mac": mac,
                "hostname": "",
                "vendor": "",
                "category": "",
                "vlan": "",
                "description": desc,
                "source": f"snmp_fdb:{target}",
                "raw": {
                    "mac": mac,
                    "bridge_port": bridge_port,
                    "ifindex": ifindex,
                    "ifdescr": ifdescr,
                },
            })
        return out

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
        mac_to_ip_global: dict[str, str] = {}

        for target in self.targets:
            log.info("SNMP: querying ARP table from %s", target)

            # Get device identity
            info = self._query_device_info(target)
            log.debug("SNMP device: %s — %s", target, info.get("name","?"))

            # Walk ARP table
            arp_entries = self._query_arp_table(target)
            log.info("SNMP: got %d ARP entries from %s", len(arp_entries), target)
            lldp_entries = self._query_lldp_neighbors(target)
            if lldp_entries:
                log.info("SNMP: got %d LLDP neighbor entries from %s", len(lldp_entries), target)
            cdp_entries = self._query_cdp_neighbors(target)
            if cdp_entries:
                log.info("SNMP: got %d CDP neighbor entries from %s", len(cdp_entries), target)
            mac_to_ip_local = {
                (e.get("mac") or "").lower(): e.get("ip", "")
                for e in arp_entries
                if e.get("ip") and e.get("mac")
            }
            mac_to_ip_global.update(mac_to_ip_local)
            fdb_entries = self._query_switch_fdb(target, mac_to_ip_global)
            if fdb_entries:
                log.info("SNMP: got %d FDB entries with IP correlation from %s", len(fdb_entries), target)

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

            # Merge LLDP/CDP neighbor hints (hostname/vendor) by management IP
            for entry in (lldp_entries + cdp_entries + fdb_entries):
                ip = entry.get("ip", "")
                if not ip:
                    continue
                existing = results.get(ip, {
                    "ip":          ip,
                    "mac":         "",
                    "hostname":    "",
                    "vendor":      "",
                    "category":    "",
                    "vlan":        "",
                    "description": "",
                    "source":      "",
                    "raw":         {},
                })
                if not existing.get("hostname") and entry.get("hostname"):
                    existing["hostname"] = entry["hostname"]
                if not existing.get("vendor") and entry.get("vendor"):
                    existing["vendor"] = entry["vendor"]
                if entry.get("description"):
                    existing["description"] = entry["description"]
                existing["source"] = entry.get("source") or existing.get("source", "")
                existing["raw"] = entry.get("raw") or existing.get("raw", {})
                results[ip] = existing

        log.info("SNMP enrichment: %d total records from %d targets",
                 len(results), len(self.targets))
        return list(results.values())
