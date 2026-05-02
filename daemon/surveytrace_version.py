"""
SurveyTrace — read release version from repo root VERSION (same file PHP uses via st_version.php).

Used for outbound User-Agent strings in sync scripts and the scanner daemon.
"""

from __future__ import annotations

from pathlib import Path

_FALLBACK = "0.13.0"


def surveytrace_version() -> str:
    root = Path(__file__).resolve().parent.parent
    vf = root / "VERSION"
    if not vf.is_file():
        return _FALLBACK
    try:
        text = vf.read_text(encoding="utf-8")
    except OSError:
        return _FALLBACK
    for line in text.splitlines():
        v = line.strip()
        if not v or v.startswith("#"):
            continue
        if len(v) > 64:
            continue
        return v
    return _FALLBACK
