"""
Phase 10 — finding triage: provenance, detection method, confidence, risk score, evidence JSON.

Used by scanner_daemon.phase_cve and collector_ingest_worker so change_detection can persist
explainable metadata alongside NVD-derived CVE rows.
"""

from __future__ import annotations

import json
from typing import Any


def build_scan_triage(
    cvss: float | None,
    *,
    matched_cpe: str,
    cpe_origin: str,
) -> dict[str, Any]:
    """
    cpe_origin: nmap_port | fingerprint (how the matched CPE was sourced on the asset).
    """
    cvss_v = float(cvss or 0.0)
    if cpe_origin == "nmap_port":
        method = "nmap_port_cpe"
        confidence = "high"
        weight = 1.0
    elif cpe_origin == "fingerprint":
        method = "asset_fingerprint_cpe"
        confidence = "medium"
        weight = 0.82
    else:
        method = "unknown"
        confidence = "low"
        weight = 0.65
    risk = round(min(100.0, max(0.0, cvss_v * 10.0 * weight)), 1)
    evidence: dict[str, Any] = {
        "matched_cpe": matched_cpe or None,
        "cpe_origin": cpe_origin or "unknown",
        "rationale": (
            "CVE matched from local NVD database using a versioned application CPE observed on the host; "
            "risk score scales CVSS by confidence in how that CPE was detected."
        ),
    }
    return {
        "provenance_source": "scanner",
        "detection_method": method,
        "confidence": confidence,
        "risk_score": risk,
        "evidence_json": json.dumps(evidence, separators=(",", ":"), ensure_ascii=False),
    }


def build_collector_triage(cvss: float | None, *, collector_id: str | None = None) -> dict[str, Any]:
    """Findings ingested from a collector payload (no local CPE correlation step on master)."""
    cvss_v = float(cvss or 0.0)
    evidence: dict[str, Any] = {
        "matched_cpe": None,
        "cpe_origin": "collector_payload",
        "rationale": (
            "Finding was submitted by a collector without SurveyTrace master-side CPE→NVD correlation metadata; "
            "treat as lower confidence unless the edge agent attached its own evidence."
        ),
    }
    if collector_id:
        evidence["collector_hint"] = collector_id[:120]
    return {
        "provenance_source": "collector",
        "detection_method": "collector_ingest",
        "confidence": "low",
        "risk_score": round(min(100.0, max(0.0, cvss_v * 10.0 * 0.55)), 1),
        "evidence_json": json.dumps(evidence, separators=(",", ":"), ensure_ascii=False),
    }
