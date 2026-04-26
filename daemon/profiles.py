"""
SurveyTrace — scan profiles

Profiles control what the scanner is allowed to do. They are the primary
safety mechanism — choosing a profile prevents accidentally running
aggressive scans against sensitive devices.

Profile hierarchy (safest to most aggressive):
  iot_safe           — passive only, ARP/ICMP, OUI/hostname/enrichment
  standard_inventory — limited ports, light banners, common services
  deep_scan          — full nmap -sV, SNMP, CVE correlation
  full_tcp           — all TCP ports (-p-), high coverage, slower
  fast_full_tcp      — all TCP ports (-p-), faster host turnover, lighter detection
  ot_careful         — passive only, explicit override required for any probing

Each profile is a dict of constraints that the daemon enforces at runtime.
The UI shows these constraints so users know what they're selecting.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanProfile:
    name:        str
    label:       str
    description: str
    icon:        str   # emoji for UI

    # Discovery
    allow_arp:        bool = True
    allow_icmp:       bool = True
    allow_tcp_ping:   bool = True   # TCP SYN/ACK ping during discovery

    # Banner / service detection
    allow_banner:     bool = False  # nmap -sV
    allow_version_intensity: int = 0   # 0-9, higher = more probes
    max_ports:        int = 0       # 0 = use profile port list
    port_list:        list[int] = field(default_factory=list)

    # Protocol-specific probing
    allow_snmp:       bool = False
    allow_ot_probes:  bool = False   # Modbus, DNP3, S7, OPC-UA etc.
    allow_mdns:       bool = True    # passive only, safe
    allow_ssdp:       bool = True    # passive only, safe

    # CVE correlation
    allow_cve:        bool = False   # only meaningful if banners enabled

    # Rate limiting
    max_rate_pps:     int  = 5      # packets per second per host
    min_delay_ms:     int  = 200    # minimum delay between hosts
    max_rate_pps_cap: int  = 10     # hard cap regardless of user setting
    per_host_probe_limit: int = 0   # 0 = no limit

    # Safety
    require_confirmation: bool = False  # prompt before running
    allow_force_mode:     bool = False  # -Pn mode allowed
    safe_for_iot:         bool = True   # shows green badge in UI
    safe_for_ot:          bool = False  # shows special OT warning if False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name":                 self.name,
            "label":                self.label,
            "description":          self.description,
            "icon":                 self.icon,
            "allow_arp":            self.allow_arp,
            "allow_icmp":           self.allow_icmp,
            "allow_tcp_ping":       self.allow_tcp_ping,
            "allow_banner":         self.allow_banner,
            "allow_version_intensity": self.allow_version_intensity,
            "max_ports":            self.max_ports,
            "port_list":            self.port_list,
            "allow_snmp":           self.allow_snmp,
            "allow_ot_probes":      self.allow_ot_probes,
            "allow_mdns":           self.allow_mdns,
            "allow_ssdp":           self.allow_ssdp,
            "allow_cve":            self.allow_cve,
            "max_rate_pps":         self.max_rate_pps,
            "min_delay_ms":         self.min_delay_ms,
            "max_rate_pps_cap":     self.max_rate_pps_cap,
            "per_host_probe_limit": self.per_host_probe_limit,
            "require_confirmation": self.require_confirmation,
            "allow_force_mode":     self.allow_force_mode,
            "safe_for_iot":         self.safe_for_iot,
            "safe_for_ot":          self.safe_for_ot,
        }


# ---------------------------------------------------------------------------
# Common port lists
# ---------------------------------------------------------------------------

# Minimal set — only the most common services, safe to probe on any network
PORTS_MINIMAL = [
    22, 80, 443, 8080, 8443,
]

# Standard set — common services including self-hosted apps
PORTS_STANDARD = [
    21, 22, 23, 25, 53, 80, 110, 143, 161, 443, 445, 465, 587, 631,
    1433, 1521, 3306, 5432, 6379, 8080, 8443, 9200, 27017,
    902, 903, 2375, 2376, 8006, 8007, 9443, 10051,
    3389, 5900, 5985, 5986,
    5060, 5061,
    1883, 8883, 8123,
    3000, 3001, 3030, 8086, 8088, 8089, 8191, 9000, 9090, 9443, 9925,
    7878, 8096, 8989, 32400, 34401,
    5080, 5341, 7070, 8000, 8001, 8081, 8082, 8101, 8181, 8383, 8888,
    5000, 5001,
    9100,
    9997,
]

# Full set — everything in SAFE_PORTS from scanner_daemon.py
PORTS_FULL = sorted(set(PORTS_STANDARD + [
    102, 502, 4840, 20000, 44818,  # OT — read-only safe
    1194, 51820,                    # VPN
    10250,                          # Kubernetes
    3100, 9091, 9093,               # Monitoring
    8384,                           # Syncthing
    5984,                           # CouchDB
    7474,                           # Neo4j
    9042,                           # Cassandra
]))

# OT-specific ports — only used in ot_careful with explicit override
PORTS_OT = [102, 502, 2222, 4840, 20000, 44818, 102, 4000, 9600, 1962]


# ---------------------------------------------------------------------------
# Profile definitions
# ---------------------------------------------------------------------------

IOT_SAFE = ScanProfile(
    name        = "iot_safe",
    label       = "IoT Safe",
    description = (
        "Passive-first discovery only. Uses ARP and ICMP to find hosts, "
        "OUI/MAC lookup and hostname resolution for identification. "
        "No banner probing, no port scanning, no SNMP, no CVE checks. "
        "Safe for smart home devices, IP cameras, industrial equipment."
    ),
    icon        = "🛡️",

    allow_arp          = True,
    allow_icmp         = True,
    allow_tcp_ping     = False,   # no TCP probes at all
    allow_banner       = False,
    allow_version_intensity = 0,
    max_ports          = 0,
    port_list          = [],      # no port scanning

    allow_snmp         = False,
    allow_ot_probes    = False,
    allow_mdns         = True,
    allow_ssdp         = True,

    allow_cve          = False,

    max_rate_pps       = 2,
    min_delay_ms       = 500,
    max_rate_pps_cap   = 5,
    per_host_probe_limit = 3,

    require_confirmation = False,
    allow_force_mode     = False,
    safe_for_iot         = True,
    safe_for_ot          = True,
)

STANDARD_INVENTORY = ScanProfile(
    name        = "standard_inventory",
    label       = "Standard Inventory",
    description = (
        "Balanced discovery with limited port scanning and light banner "
        "probing. Identifies common services on well-known ports. "
        "Suitable for general-purpose networks and most server environments. "
        "Not recommended for sensitive IoT or OT environments."
    ),
    icon        = "📋",

    allow_arp          = True,
    allow_icmp         = True,
    allow_tcp_ping     = True,
    allow_banner       = True,
    allow_version_intensity = 3,   # light — fewer probes than default
    max_ports          = len(PORTS_STANDARD),
    port_list          = PORTS_STANDARD,

    allow_snmp         = False,
    allow_ot_probes    = False,
    allow_mdns         = True,
    allow_ssdp         = True,

    allow_cve          = True,

    max_rate_pps       = 50,
    min_delay_ms       = 50,
    max_rate_pps_cap   = 100,
    per_host_probe_limit = 0,

    require_confirmation = False,
    allow_force_mode     = True,
    safe_for_iot         = False,
    safe_for_ot          = False,
)

DEEP_SCAN = ScanProfile(
    name        = "deep_scan",
    label       = "Deep Scan",
    description = (
        "Full service detection with nmap -sV at high intensity, SNMP "
        "polling, and comprehensive CVE correlation. Generates significant "
        "network traffic. Requires confirmation. Not safe for IoT or OT. "
        "Use for targeted investigation of specific hosts."
    ),
    icon        = "🔬",

    allow_arp          = True,
    allow_icmp         = True,
    allow_tcp_ping     = True,
    allow_banner       = True,
    allow_version_intensity = 7,   # aggressive version detection
    max_ports          = len(PORTS_FULL),
    port_list          = PORTS_FULL,

    allow_snmp         = True,
    allow_ot_probes    = False,    # still off by default — explicit OT is ot_careful
    allow_mdns         = True,
    allow_ssdp         = True,

    allow_cve          = True,

    max_rate_pps       = 100,
    min_delay_ms       = 10,
    max_rate_pps_cap   = 500,
    per_host_probe_limit = 0,

    require_confirmation = True,   # prompt before running
    allow_force_mode     = True,
    safe_for_iot         = False,
    safe_for_ot          = False,
)

FULL_TCP = ScanProfile(
    name        = "full_tcp",
    label       = "Full TCP",
    description = (
        "Scans all 65,535 TCP ports with service detection (-sV -p-). "
        "Useful when services run on non-standard ports or are hidden from "
        "common-port profiles. High traffic and slower runtime; use carefully."
    ),
    icon        = "🧭",

    allow_arp          = True,
    allow_icmp         = True,
    allow_tcp_ping     = True,
    allow_banner       = True,
    allow_version_intensity = 5,
    max_ports          = 65535,
    port_list          = [],      # scanner_daemon interprets full_tcp as -p-

    allow_snmp         = True,
    allow_ot_probes    = False,
    allow_mdns         = True,
    allow_ssdp         = True,

    allow_cve          = True,

    max_rate_pps       = 60,
    min_delay_ms       = 25,
    max_rate_pps_cap   = 200,
    per_host_probe_limit = 0,

    require_confirmation = True,
    allow_force_mode     = True,
    safe_for_iot         = False,
    safe_for_ot          = False,
)

FAST_FULL_TCP = ScanProfile(
    name        = "fast_full_tcp",
    label       = "Fast Full TCP",
    description = (
        "Scans all 65,535 TCP ports with lighter service detection for faster "
        "host turnover. Designed for broader sweeps where responsiveness matters "
        "more than deep version fingerprinting accuracy."
    ),
    icon        = "⚡",

    allow_arp          = True,
    allow_icmp         = True,
    allow_tcp_ping     = True,
    allow_banner       = True,
    allow_version_intensity = 2,
    max_ports          = 65535,
    port_list          = [],      # scanner_daemon interprets *_full_tcp as -p-

    allow_snmp         = True,
    allow_ot_probes    = False,
    allow_mdns         = True,
    allow_ssdp         = True,

    allow_cve          = True,

    max_rate_pps       = 80,
    min_delay_ms       = 10,
    max_rate_pps_cap   = 300,
    per_host_probe_limit = 0,

    require_confirmation = True,
    allow_force_mode     = True,
    safe_for_iot         = False,
    safe_for_ot          = False,
)

OT_CAREFUL = ScanProfile(
    name        = "ot_careful",
    label       = "OT Careful",
    description = (
        "Designed for operational technology environments. Passive discovery "
        "only by default — ARP and ICMP to identify hosts, OUI/MAC lookup "
        "for classification. OT protocol probing (Modbus, DNP3, S7, OPC-UA) "
        "is disabled and requires explicit override. Any active probing "
        "requires confirmation. Never use deep scan on OT networks."
    ),
    icon        = "⚠️",

    allow_arp          = True,
    allow_icmp         = True,
    allow_tcp_ping     = False,
    allow_banner       = False,
    allow_version_intensity = 0,
    max_ports          = 0,
    port_list          = [],

    allow_snmp         = False,
    allow_ot_probes    = False,   # never by default — explicit override only
    allow_mdns         = True,
    allow_ssdp         = False,   # SSDP can interfere with some OT gear

    allow_cve          = False,

    max_rate_pps       = 1,
    min_delay_ms       = 1000,
    max_rate_pps_cap   = 2,
    per_host_probe_limit = 2,

    require_confirmation = True,
    allow_force_mode     = False,
    safe_for_iot         = True,
    safe_for_ot          = True,
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

PROFILES: dict[str, ScanProfile] = {
    "iot_safe":           IOT_SAFE,
    "standard_inventory": STANDARD_INVENTORY,
    "deep_scan":          DEEP_SCAN,
    "full_tcp":           FULL_TCP,
    "fast_full_tcp":      FAST_FULL_TCP,
    "ot_careful":         OT_CAREFUL,
}

DEFAULT_PROFILE = "standard_inventory"


def get_profile(name: str) -> ScanProfile:
    """Return a profile by name, falling back to standard_inventory."""
    return PROFILES.get(name, STANDARD_INVENTORY)


def list_profiles() -> list[dict]:
    """Return all profiles as dicts for API/UI consumption."""
    return [p.to_dict() for p in PROFILES.values()]


def validate_phases(profile: ScanProfile, requested_phases: list[str]) -> list[str]:
    """
    Filter requested phases against what the profile allows.
    Returns the safe subset of phases.
    """
    allowed = ["passive"]   # passive (ARP/mDNS) always allowed if profile permits

    if profile.allow_icmp:
        allowed.append("icmp")

    if profile.allow_banner and (profile.port_list or profile.name in ("full_tcp", "fast_full_tcp")):
        allowed.append("banner")
        allowed.append("fingerprint")

    if profile.allow_cve and profile.allow_banner:
        allowed.append("cve")

    # Return intersection of requested and allowed, preserving order
    return [p for p in requested_phases if p in allowed]
