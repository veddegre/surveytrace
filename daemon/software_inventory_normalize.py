"""
Normalized software identity helpers for credentialed package inventory.

Preserves raw distro versions; does not invent semver or strip epoch/release blindly.
"""

from __future__ import annotations

import re
from typing import Any

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_NON_PRINT = re.compile(r"[^\x20-\x7E]+")
_SEP_COLLAPSE = re.compile(r"[\s_/]+")


def package_manager_to_ecosystem(package_manager: str) -> str:
    x = (package_manager or "").strip().lower()
    if x == "dpkg":
        return "dpkg"
    if x == "rpm":
        return "rpm"
    return "generic"


def normalize_separators_for_name(s: str) -> str:
    t = _SEP_COLLAPSE.sub("-", (s or "").strip().lower())
    t = re.sub(r"-{2,}", "-", t)
    return t.strip("-")


def normalize_package_name_fields(raw_name: str) -> tuple[str, str] | None:
    """Return (canonical_name, normalized_name) or None if unusable."""
    n = _CTRL.sub("", (raw_name or "").strip())
    n = _NON_PRINT.sub("", n)[:500]
    if not n:
        return None
    nn = normalize_separators_for_name(n)
    if not nn:
        return None
    return n[:500], nn[:500]


def sanitize_version_raw(version: str, *, max_len: int = 500) -> str:
    v = _CTRL.sub("", (version or "").strip())
    v = _NON_PRINT.sub("", v)[:max_len]
    return v


def sanitize_arch(arch: str | None, *, max_len: int = 64) -> str:
    if arch is None:
        return ""
    a = _CTRL.sub("", str(arch).strip())
    a = _NON_PRINT.sub("", a)[:max_len]
    return a


def rpm_version_foundation_fields(version_raw: str) -> dict[str, str | None]:
    """
    Optional rpm-style hints only; version_raw is always preserved separately.
    Does not parse NEVRA into semver.
    """
    raw = sanitize_version_raw(version_raw, max_len=500)
    if not raw:
        return {"version_normalized": None, "epoch": None, "package_release": None}
    epoch: str | None = None
    rest = raw
    m = re.match(r"^(\d+):(.+)$", raw)
    if m:
        epoch = m.group(1)
        rest = m.group(2)
    vr = rest
    package_release: str | None = None
    if "." in rest or "-" in rest:
        parts = rest.rsplit("-", 1)
        if len(parts) == 2 and parts[1] and re.search(r"[a-zA-Z]", parts[1]):
            vr = parts[0]
            package_release = parts[1][:200]
    vn = vr[:300] if vr else None
    return {
        "version_normalized": vn,
        "epoch": epoch,
        "package_release": package_release,
    }


def version_sidecar_for_row(ecosystem: str, version_raw: str) -> dict[str, Any]:
    eco = (ecosystem or "").strip().lower()
    if eco == "rpm":
        d = rpm_version_foundation_fields(version_raw)
        return {
            "version_normalized": d.get("version_normalized"),
            "epoch": d.get("epoch"),
            "package_release": d.get("package_release"),
            "distro_release": None,
        }
    return {
        "version_normalized": None,
        "epoch": None,
        "package_release": None,
        "distro_release": None,
    }
