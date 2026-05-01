"""
SurveyTrace remote collector agent (MVP).

Flow:
  1) register (one-time install token) to obtain collector bearer token
  2) heartbeat/checkin periodically
  3) poll jobs, run local scan command, submit chunked payloads
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from collector_parity_runner import run_collector_parity

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("surveytrace-collector")


def _http_error_body(exc: urllib.error.HTTPError) -> str:
    try:
        raw = exc.read().decode("utf-8", errors="replace")
    except Exception:
        return ""
    return raw.strip()[:2000]


def _http_json(url: str, body: dict, headers: dict[str, str], timeout: int = 20) -> dict:
    req = urllib.request.Request(
        url,
        method="POST",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    doc = json.loads(raw) if raw.strip() else {}
    if not isinstance(doc, dict):
        raise RuntimeError("bad JSON response")
    return doc


def load_cfg(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_cfg(path: Path, cfg: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")


def run_scan_job(job: dict) -> dict:
    target = str(job.get("target_cidr", "")).strip()
    if target == "":
        return {"scan_job": {"status": "failed", "error_msg": "missing target"}, "assets": [], "findings": [], "scan_log": []}
    started = time.time()
    payload = run_collector_parity(job)
    try:
        sdoc = json.loads(payload.get("scan_job", {}).get("summary_json", "") or "{}")
    except Exception:
        sdoc = {}
    sdoc["collector_mode"] = True
    sdoc["runtime_sec"] = round(time.time() - started, 2)
    payload.setdefault("scan_job", {})["summary_json"] = json.dumps(sdoc, separators=(",", ":"), ensure_ascii=False)
    return payload


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(Path.home() / ".surveytrace" / "collector.json"))
    args = ap.parse_args()
    cfg_path = Path(args.config)
    cfg = load_cfg(cfg_path)

    server = str(cfg.get("server_base_url", "")).rstrip("/")
    if server == "":
        raise SystemExit("Missing server_base_url in config")

    # Registration on first run.
    if not cfg.get("collector_token"):
        install_token = str(cfg.get("install_token", "")).strip()
        if install_token == "":
            raise SystemExit("Missing install_token for first registration")
        try:
            reg = _http_json(
                f"{server}/api/collector_checkin.php",
                {
                    "action": "register",
                    "name": cfg.get("name", socket.gethostname()),
                    "site_label": cfg.get("site_label", ""),
                    "version": cfg.get("version", "collector-agent-mvp"),
                    "capabilities": {"nmap": True},
                },
                headers={"X-Collector-Install-Token": install_token},
            )
        except urllib.error.HTTPError as he:
            if he.code in (401, 403):
                raise SystemExit("Collector install token denied; generate/save a new install token and re-register")
            raise
        if not reg.get("ok"):
            raise SystemExit(f"Registration failed: {reg}")
        cfg["collector_id"] = int(reg["collector_id"])
        cfg["collector_token"] = str(reg["token"])
        save_cfg(cfg_path, cfg)

    token = str(cfg.get("collector_token", ""))
    if token == "":
        raise SystemExit("Missing collector_token")

    pending_err = ""

    while True:
        try:
            # Heartbeat (surface last loop failure to master for ops visibility)
            _http_json(
                f"{server}/api/collector_checkin.php",
                {
                    "action": "heartbeat",
                    "version": cfg.get("version", "collector-agent-mvp"),
                    "capabilities": {"nmap": True},
                    "last_error": pending_err[:2000],
                },
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )
            pending_err = ""

            poll = _http_json(
                f"{server}/api/collector_jobs.php",
                {"max_jobs": int(cfg.get("max_jobs", 2))},
                headers={"Authorization": f"Bearer {token}"},
                timeout=20,
            )
            jobs = poll.get("jobs", []) if isinstance(poll, dict) else []
            if not isinstance(jobs, list):
                jobs = []
            for job in jobs:
                master_job_id = int(job.get("job_id", 0) or 0)
                if master_job_id <= 0:
                    log.error("Poll returned job without job_id: %s", job)
                    pending_err = "Invalid job payload from master (missing job_id)"
                    continue
                log.info("Running collector job master_id=%s target=%s", master_job_id, job.get("target_cidr"))
                payload = run_scan_job(job)
                sub_id = f"job-{master_job_id}-{int(time.time())}"
                sub = _http_json(
                    f"{server}/api/collector_submit.php",
                    {
                        "job_id": master_job_id,
                        "lease_token": str(job.get("lease_token", "")),
                        "submission_id": sub_id,
                        "chunk_index": 0,
                        "chunk_count": 1,
                        "payload": payload,
                    },
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=120,
                )
                log.info(
                    "Submitted results master_job_id=%s submission_id=%s ok=%s",
                    master_job_id,
                    sub_id,
                    sub.get("ok") if isinstance(sub, dict) else sub,
                )
        except urllib.error.HTTPError as he:
            detail = _http_error_body(he)
            if he.code == 401:
                raise SystemExit("Collector token rejected; rotate/re-register required")
            log.error("HTTP %s from %s: %s", he.code, getattr(he, "url", "?"), detail or he.reason)
            pending_err = f"HTTP {he.code}: {detail or he.reason}"[:2000]
        except Exception as e:
            log.exception("Collector loop error: %s", e)
            pending_err = str(e)[:2000]
        time.sleep(max(5, int(cfg.get("poll_interval_sec", 20))))


if __name__ == "__main__":
    main()
