"""
SurveyTrace — UniFi enrichment source

Supports UniFi OS (UDM, UDM-Pro, UDM-SE, Dream Router) via the local
UniFi Network API. Also supports legacy UniFi Controller (self-hosted).

Config keys:
    host          — controller IP or hostname (e.g. "192.168.86.1")
    username      — local admin username (NOT Ubiquiti cloud account)
    password      — local admin password
    port          — API port (default: 443 for UDM, 8443 for legacy)
    site          — site name (default: "default")
    verify_ssl    — bool, default False (UDM uses self-signed cert)
    controller_type — "udm" | "legacy" (default: "udm")
    timeout       — request timeout seconds (default: 10)

UniFi OS (UDM) API notes:
    Login:  POST /api/auth/login
    Cookie: unifises + csrf token
    Clients: GET /proxy/network/api/s/{site}/stat/sta  (connected)
             GET /proxy/network/api/s/{site}/rest/user (all known)

Legacy controller:
    Login:  POST /api/login
    Clients: GET /api/s/{site}/stat/sta
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
import ssl
from typing import Any

from sources import EnrichmentSource, register

log = logging.getLogger("surveytrace.enrichment.unifi")


@register
class UniFiSource(EnrichmentSource):
    name = "unifi"

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self.host           = config.get("host", "")
        self.username       = config.get("username", "")
        self.password       = config.get("password", "")
        self.port           = int(config.get("port", 443))
        self.site           = config.get("site", "default")
        self.verify_ssl     = bool(config.get("verify_ssl", False))
        self.controller_type= config.get("controller_type", "udm")
        self.timeout        = int(config.get("timeout", 10))
        self._cookies: dict[str, str] = {}
        self._csrf: str = ""

    # -----------------------------------------------------------------------
    # SSL context
    # -----------------------------------------------------------------------
    def _ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    # -----------------------------------------------------------------------
    # HTTP helpers
    # -----------------------------------------------------------------------
    def _base_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        url     = self._base_url() + path
        data    = json.dumps(body).encode() if body else None
        headers = {
            "Content-Type": "application/json",
            "Accept":       "application/json",
        }
        if self._cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
        if self._csrf:
            headers["X-Csrf-Token"] = self._csrf

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx(), timeout=self.timeout) as resp:
                # Capture cookies from response
                raw_cookies = resp.headers.get("Set-Cookie", "")
                if raw_cookies:
                    for part in raw_cookies.split(","):
                        kv = part.strip().split(";")[0].strip()
                        if "=" in kv:
                            k, v = kv.split("=", 1)
                            self._cookies[k.strip()] = v.strip()
                # Capture CSRF token
                csrf = resp.headers.get("X-Csrf-Token", "")
                if csrf:
                    self._csrf = csrf
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {e.code} from {url}: {body[:200]}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"Connection failed to {url}: {e.reason}") from e

    # -----------------------------------------------------------------------
    # Authentication
    # -----------------------------------------------------------------------
    def _login(self) -> None:
        self._cookies = {}
        self._csrf    = ""

        if self.controller_type == "udm":
            # UniFi OS login
            resp = self._request("POST", "/api/auth/login", {
                "username": self.username,
                "password": self.password,
                "remember": False,
            })
            if not resp.get("unique_id") and not resp.get("username"):
                raise RuntimeError(f"UniFi OS login failed: {resp}")
            log.debug("UniFi OS login OK as %s", self.username)
        else:
            # Legacy controller login
            resp = self._request("POST", "/api/login", {
                "username": self.username,
                "password": self.password,
            })
            if resp.get("meta", {}).get("rc") != "ok":
                raise RuntimeError(f"UniFi legacy login failed: {resp}")
            log.debug("UniFi legacy login OK")

    def _logout(self) -> None:
        try:
            if self.controller_type == "udm":
                self._request("POST", "/api/auth/logout", {})
            else:
                self._request("POST", "/api/logout", {})
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Client data fetching
    # -----------------------------------------------------------------------
    def _client_path(self, endpoint: str) -> str:
        if self.controller_type == "udm":
            return f"/proxy/network/api/s/{self.site}/{endpoint}"
        else:
            return f"/api/s/{self.site}/{endpoint}"

    def _fetch_clients(self) -> list[dict]:
        """Fetch currently connected clients."""
        try:
            resp = self._request("GET", self._client_path("stat/sta"))
            return resp.get("data", [])
        except Exception as e:
            log.warning("Could not fetch connected clients: %s", e)
            return []

    def _fetch_known_devices(self) -> list[dict]:
        """Fetch all known devices (including offline)."""
        try:
            resp = self._request("GET", self._client_path("rest/user"))
            return resp.get("data", [])
        except Exception as e:
            log.warning("Could not fetch known devices: %s", e)
            return []

    def _fetch_network_devices(self) -> list[dict]:
        """Fetch UniFi network devices (APs, switches, gateways)."""
        try:
            resp = self._request("GET", self._client_path("stat/device"))
            return resp.get("data", [])
        except Exception as e:
            log.warning("Could not fetch network devices: %s", e)
            return []

    # -----------------------------------------------------------------------
    # Data normalization
    # -----------------------------------------------------------------------
    def _normalize_client(self, client: dict, source_tag: str = "unifi_client") -> dict | None:
        """Convert a UniFi client record to our standard enrichment format."""
        ip  = client.get("ip", "")
        mac = (client.get("mac", "") or "").lower()

        if not ip and not mac:
            return None

        # Hostname — prefer user-set alias, fall back to hostname, then name
        hostname = (
            client.get("name", "")
            or client.get("hostname", "")
            or client.get("noted_hostname", "")
            or ""
        ).strip()

        # Vendor from UniFi's own OUI lookup
        vendor = (client.get("oui", "") or "").strip()

        # VLAN
        vlan = str(client.get("vlan", "") or client.get("network", "") or "")

        # Category hint from device type
        category = ""
        device_type = str(client.get("dev_cat", "") or "").lower()
        if "phone"  in device_type: category = "ws"
        elif "tablet" in device_type: category = "ws"
        elif "laptop" in device_type: category = "ws"
        elif "printer" in device_type: category = "prn"
        elif "camera" in device_type: category = "iot"
        elif "tv"     in device_type: category = "iot"
        elif "media"  in device_type: category = "iot"

        return {
            "ip":          ip,
            "mac":         mac,
            "hostname":    hostname,
            "vendor":      vendor,
            "category":    category,
            "vlan":        vlan,
            "description": client.get("noted_hostname", "") or "",
            "source":      source_tag,
            "last_seen":   client.get("last_seen", 0),
            "is_wired":    bool(client.get("is_wired", False)),
            "ap_mac":      client.get("ap_mac", "") or "",
            "signal":      client.get("signal", None),
            "raw":         client,
        }

    def _normalize_device(self, device: dict) -> dict | None:
        """Convert a UniFi network device (AP/switch/GW) to enrichment format."""
        ip  = device.get("ip", "")
        mac = (device.get("mac", "") or "").lower()
        if not ip and not mac:
            return None

        model    = device.get("model", "")
        name     = device.get("name", "") or device.get("hostname", "") or model or ""
        dev_type = device.get("type", "").lower()

        # Map UniFi device types to our categories
        category = "net"   # all UniFi devices are network gear
        vendor   = "Ubiquiti Networks"

        model_map = {
            "ugw":   "UniFi Security Gateway",
            "udm":   "UniFi Dream Machine",
            "udmpro":"UniFi Dream Machine Pro",
            "uxg":   "UniFi Express Gateway",
            "uap":   "UniFi Access Point",
            "usw":   "UniFi Switch",
            "uck":   "UniFi Cloud Key",
        }
        for k, v in model_map.items():
            if model.lower().startswith(k):
                vendor = f"Ubiquiti Networks — {v}"
                break

        return {
            "ip":          ip,
            "mac":         mac,
            "hostname":    name,
            "vendor":      vendor,
            "category":    category,
            "vlan":        "",
            "description": f"UniFi {dev_type} — model: {model}",
            "source":      "unifi_device",
            "last_seen":   device.get("last_seen", 0),
            "is_wired":    True,
            "ap_mac":      "",
            "signal":      None,
            "raw":         device,
        }

    # -----------------------------------------------------------------------
    # Public interface
    # -----------------------------------------------------------------------
    def test_connection(self) -> tuple[bool, str]:
        if not self.host or not self.username or not self.password:
            return False, "Missing host, username, or password"
        try:
            self._login()
            self._logout()
            return True, f"Connected to UniFi controller at {self.host}"
        except Exception as e:
            return False, str(e)

    def fetch_all(self) -> list[dict]:
        """
        Fetch all clients (connected + known) and network devices.
        Merges known device records with live client records so we get
        hostnames for offline devices too.
        """
        results: dict[str, dict] = {}   # keyed by MAC

        try:
            self._login()

            # 1. All known clients (includes offline, has user-set names)
            known = self._fetch_known_devices()
            log.info("UniFi: fetched %d known clients", len(known))
            for c in known:
                norm = self._normalize_client(c, "unifi_known")
                if norm and norm["mac"]:
                    results[norm["mac"]] = norm

            # 2. Connected clients (live data — fresher IPs)
            connected = self._fetch_clients()
            log.info("UniFi: fetched %d connected clients", len(connected))
            for c in connected:
                norm = self._normalize_client(c, "unifi_client")
                if not norm:
                    continue
                key = norm["mac"] or norm["ip"]
                if key in results:
                    # Merge: connected data has fresher IP/signal
                    results[key].update({
                        "ip":       norm["ip"] or results[key]["ip"],
                        "signal":   norm["signal"],
                        "ap_mac":   norm["ap_mac"],
                        "source":   "unifi_client",
                    })
                    if norm["hostname"] and not results[key]["hostname"]:
                        results[key]["hostname"] = norm["hostname"]
                else:
                    results[key] = norm

            # 3. Network devices (APs, switches, GW)
            devices = self._fetch_network_devices()
            log.info("UniFi: fetched %d network devices", len(devices))
            for d in devices:
                norm = self._normalize_device(d)
                if not norm:
                    continue
                key = norm["mac"] or norm["ip"]
                results[key] = norm  # network devices always win

        except Exception as e:
            log.error("UniFi fetch_all error: %s", e)
            raise
        finally:
            try:
                self._logout()
            except Exception:
                pass

        out = list(results.values())
        log.info("UniFi enrichment: %d total records", len(out))
        return out
