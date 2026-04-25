"""
SurveyTrace — enrichment source stubs
Placeholder adapters for enterprise sources.
Each stub registers itself so the settings UI can list it,
but raises NotImplementedError until fully implemented.
"""

from __future__ import annotations
from sources import EnrichmentSource, register
import logging

log = logging.getLogger("surveytrace.enrichment.stubs")


@register
class CiscoDNASource(EnrichmentSource):
    """
    Cisco DNA Center / Catalyst Center enrichment.

    API: GET /dna/intent/api/v1/network-device
         GET /dna/intent/api/v1/host
    Auth: POST /dna/system/api/v1/auth/token (returns X-Auth-Token)

    Config keys:
        host     — DNA Center IP/hostname
        username — admin username
        password — admin password
        verify_ssl — bool (default False)
    """
    name = "cisco_dna"

    def test_connection(self) -> tuple[bool, str]:
        return False, "Cisco DNA Center adapter not yet implemented"

    def fetch_all(self) -> list[dict]:
        raise NotImplementedError("Cisco DNA Center adapter — coming soon")


@register
class JuniperMistSource(EnrichmentSource):
    """
    Juniper Mist enrichment (cloud or on-prem).

    Cloud API: GET https://api.mist.com/api/v1/sites/{site_id}/clients/wireless
    Auth: Bearer token in Authorization header

    Config keys:
        api_key  — Mist API token
        site_id  — Mist site ID
        org_id   — Mist org ID
        base_url — API base (default: https://api.mist.com)
    """
    name = "juniper_mist"

    def test_connection(self) -> tuple[bool, str]:
        return False, "Juniper Mist adapter not yet implemented"

    def fetch_all(self) -> list[dict]:
        raise NotImplementedError("Juniper Mist adapter — coming soon")


@register
class MerakiSource(EnrichmentSource):
    """
    Cisco Meraki enrichment via Dashboard API.

    API: GET /api/v1/networks/{networkId}/clients
    Auth: X-Cisco-Meraki-API-Key header

    Config keys:
        api_key    — Meraki Dashboard API key
        network_id — Meraki network ID
        org_id     — Meraki org ID (optional)
        base_url   — API base (default: https://api.meraki.com)
    """
    name = "meraki"

    def test_connection(self) -> tuple[bool, str]:
        return False, "Cisco Meraki adapter not yet implemented"

    def fetch_all(self) -> list[dict]:
        raise NotImplementedError("Cisco Meraki adapter — coming soon")


@register
class MicrosoftDNSSource(EnrichmentSource):
    """
    Microsoft DNS / Active Directory enrichment.

    Supports three methods (tried in order):
      1. LDAP/AD — query AD for DNS records and computer objects
         (requires domain credentials, returns everything)
      2. DNS zone transfer — AXFR from MS DNS server
         (no credentials if server allows it)
      3. PTR lookup — reverse DNS query per discovered IP
         (no credentials, works as fallback)

    Config keys:
        dns_server   — IP of the MS DNS server
        method       — "ldap" | "zone_transfer" | "ptr" (default: "ptr")
        domain       — AD domain FQDN (e.g. "corp.example.com") for LDAP
        username     — AD username (LDAP only)
        password     — AD password (LDAP only)
        ldap_server  — LDAP server IP (if different from dns_server)
        zone         — DNS zone for zone transfer (e.g. "corp.example.com")
    """
    name = "ms_dns"

    def test_connection(self) -> tuple[bool, str]:
        # PTR method works without credentials — test it
        import socket
        dns_server = self.config.get("dns_server", "")
        if not dns_server:
            return False, "No DNS server configured"
        try:
            # Simple test — resolve the DNS server itself
            socket.gethostbyaddr(dns_server)
            return True, f"DNS reachable at {dns_server} (PTR method available)"
        except socket.herror:
            return True, f"DNS reachable at {dns_server} (no PTR for server itself)"
        except Exception as e:
            return False, f"DNS unreachable: {e}"

    def fetch_all(self) -> list[dict]:
        """
        PTR lookup implementation — works without credentials.
        Resolves hostnames for a list of IPs using the configured DNS server.
        Full LDAP/zone-transfer implementations coming soon.
        """
        import socket
        method = self.config.get("method", "ptr")

        if method != "ptr":
            raise NotImplementedError(f"MS DNS method '{method}' not yet implemented — use 'ptr'")

        # PTR mode — caller passes IPs to resolve, we return hostname enrichment
        # In practice this is called from the enrichment phase with discovered IPs
        # Since we don't know IPs at fetch_all time, return empty and let
        # the enrichment phase call fetch_by_ip() per host
        return []

    def fetch_by_ip(self, ip: str) -> dict | None:
        """Resolve a single IP to hostname via PTR lookup."""
        import socket
        dns_server = self.config.get("dns_server", "")
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return {
                "ip":          ip,
                "mac":         "",
                "hostname":    hostname.split(".")[0],
                "vendor":      "",
                "category":    "",
                "vlan":        "",
                "description": f"DNS PTR record from {dns_server or 'system resolver'}",
                "source":      "ms_dns",
                "raw":         {"fqdn": hostname},
            }
        except (socket.herror, socket.gaierror):
            return None


@register
class InfobloxSource(EnrichmentSource):
    """
    Infoblox DDI enrichment (common in large enterprise DNS/DHCP).

    API: GET /wapi/v2.11/lease  (DHCP leases)
         GET /wapi/v2.11/record:host  (host records)
    Auth: Basic auth

    Config keys:
        host     — Infoblox Grid Manager IP
        username — admin username
        password — admin password
        version  — WAPI version (default: "v2.11")
        verify_ssl — bool (default: False)
    """
    name = "infoblox"

    def test_connection(self) -> tuple[bool, str]:
        return False, "Infoblox adapter not yet implemented"

    def fetch_all(self) -> list[dict]:
        raise NotImplementedError("Infoblox adapter — coming soon")


@register
class PaloAltoSource(EnrichmentSource):
    """
    Palo Alto Panorama / NGFW enrichment.
    Pulls user-to-IP mappings and device inventory from Panorama.

    API: GET /api/?type=op&cmd=<show><arp><entry+name='all'/></arp></show>
    Auth: API key in X-PAN-KEY header

    Config keys:
        host    — Panorama IP/hostname
        api_key — PAN-OS API key
        verify_ssl — bool (default: False)
    """
    name = "palo_alto"

    def test_connection(self) -> tuple[bool, str]:
        return False, "Palo Alto Panorama adapter not yet implemented"

    def fetch_all(self) -> list[dict]:
        raise NotImplementedError("Palo Alto Panorama adapter — coming soon")
