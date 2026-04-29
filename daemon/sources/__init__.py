"""
SurveyTrace — enrichment source base class and registry

Each enrichment source is a class that implements the EnrichmentSource
interface. Sources are registered in the SOURCES dict and instantiated
from config stored in the enrichment_sources table.

Standard enrichment result:
{
    "ip":          "192.168.86.5",
    "mac":         "fc:3f:db:0f:6f:13",
    "hostname":    "proxmox-01",
    "vendor":      "Hewlett Packard",
    "category":    "hv",           # optional hint — scanner fingerprint wins
    "vlan":        "10",
    "description": "Server room rack 2",
    "source":      "unifi",
    "raw":         {}              # raw data from the source for debugging
}
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any
import logging
import os
from pathlib import Path

log = logging.getLogger("surveytrace.enrichment")


class EnrichmentSource(ABC):
    """Base class for all enrichment sources."""

    name: str = "base"

    def __init__(self, config: dict[str, Any]):
        self.config = config

    @abstractmethod
    def test_connection(self) -> tuple[bool, str]:
        """
        Test connectivity to the source.
        Returns (success: bool, message: str)
        """
        ...

    @abstractmethod
    def fetch_all(self) -> list[dict]:
        """
        Fetch all known clients/hosts from the source.
        Returns list of enrichment result dicts.
        """
        ...

    def fetch_by_ip(self, ip: str) -> dict | None:
        """
        Fetch enrichment data for a specific IP.
        Default implementation calls fetch_all() and filters.
        Override for sources that support targeted queries.
        """
        all_data = self.fetch_all()
        for entry in all_data:
            if entry.get("ip") == ip:
                return entry
        return None

    def fetch_by_mac(self, mac: str) -> dict | None:
        """Fetch enrichment data for a specific MAC address."""
        norm = mac.lower().replace("-", ":")
        all_data = self.fetch_all()
        for entry in all_data:
            if (entry.get("mac") or "").lower() == norm:
                return entry
        return None


# ---------------------------------------------------------------------------
# Registry — maps source type names to classes
# ---------------------------------------------------------------------------
_REGISTRY: dict[str, type[EnrichmentSource]] = {}


def register(cls: type[EnrichmentSource]) -> type[EnrichmentSource]:
    """Decorator to register an enrichment source class."""
    _REGISTRY[cls.name] = cls
    return cls


def get_source_class(name: str) -> type[EnrichmentSource] | None:
    """Return the class for a given source type name."""
    return _REGISTRY.get(name)


def available_sources() -> list[str]:
    """Return list of registered source type names."""
    return list(_REGISTRY.keys())


def load_source(source_row: dict) -> EnrichmentSource | None:
    """
    Instantiate an enrichment source from a database row.
    source_row should have: {type, config_json, ...}
    """
    import json
    source_type = source_row.get("source_type", "")
    cls = get_source_class(source_type)
    if not cls:
        log.warning("Unknown enrichment source type: %s", source_type)
        return None
    try:
        config = json.loads(source_row.get("config_json") or "{}")
        return cls(config)
    except Exception as e:
        log.error("Failed to instantiate source %s: %s", source_type, e)
        return None


def _default_enrichment_roots() -> list[Path]:
    """
    Default jailed roots for file-based enrichment sources.
    Override with SURVEYTRACE_ENRICH_PATH_ROOTS (os.pathsep-separated).
    """
    env = (os.getenv("SURVEYTRACE_ENRICH_PATH_ROOTS") or "").strip()
    vals = [v.strip() for v in env.split(os.pathsep)] if env else []
    if not vals:
        # Common operator-managed locations + local app data dir
        vals = ["/var/log", "/var/lib", "/opt/surveytrace/data", str(Path(__file__).resolve().parents[2] / "data")]
    roots: list[Path] = []
    for v in vals:
        if not v:
            continue
        try:
            roots.append(Path(v).resolve())
        except Exception:
            continue
    return roots


def _is_relative_to(path_obj: Path, root_obj: Path) -> bool:
    try:
        path_obj.relative_to(root_obj)
        return True
    except ValueError:
        return False


def resolve_jailed_path(path_raw: str, extra_roots: list[str] | None = None) -> Path | None:
    """
    Resolve and validate a file path against allowed root directories.
    Returns resolved Path if allowed and present, else None.
    """
    s = (path_raw or "").strip()
    if not s:
        return None
    try:
        p = Path(s).expanduser().resolve()
    except Exception:
        return None
    allowed_roots = list(_default_enrichment_roots())
    for r in (extra_roots or []):
        rr = (r or "").strip()
        if not rr:
            continue
        try:
            allowed_roots.append(Path(rr).expanduser().resolve())
        except Exception:
            continue
    if not any(_is_relative_to(p, root) for root in allowed_roots):
        log.warning("Rejected enrichment file path outside jail: %s", s)
        return None
    if not p.exists() or not p.is_file():
        return None
    return p
