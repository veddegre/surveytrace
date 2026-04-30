"""
SurveyTrace — scanner daemon
Polls scan_jobs for queued work, runs the configured phases,
writes results back to SQLite.

Run via systemd or supervisor:
    python3 /opt/surveytrace/daemon/scanner_daemon.py

Requirements:
    pip install scapy python-nmap requests
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Generator

from ai_cloud_client import _openwebui_base_ok, cloud_chat_completion

# Third-party — install with pip
try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False
    logging.warning("python-nmap not found — port scanning disabled")

try:
    from scapy.all import ARP, Ether, srp, sniff, DNSQR, DNS
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    logging.warning("scapy not found — passive discovery disabled")

from fingerprint import (
    cpe_uri_from_port_fragment,
    fingerprint,
    classify_from_ports,
    classify_from_hostname,
    load_external_oui_map,
    oui_lookup,
    vendor_hint_from_port_cpe,
    _printer_banner_conflicts_with_homelab_ports,
)
from profiles import get_profile, validate_phases, PROFILES, DEFAULT_PROFILE, PORTS_STANDARD

# Enrichment sources — import all to trigger registration
try:
    import sources.unifi   # noqa: F401
    import sources.snmp    # noqa: F401
    import sources.dhcp    # noqa: F401
    import sources.dns_logs  # noqa: F401
    import sources.firewall_logs  # noqa: F401
    import sources.stubs   # noqa: F401
    from sources import load_source
    HAS_ENRICHMENT = True
except ImportError as e:
    log.warning("Enrichment sources unavailable: %s", e)
    HAS_ENRICHMENT = False
    def load_source(row): return None

# ---------------------------------------------------------------------------
# Hostname resolution — tries multiple strategies
# ---------------------------------------------------------------------------
def resolve_hostname(ip: str) -> str:
    """
    Try to resolve a hostname for an IP using multiple strategies:
    1. Reverse DNS (PTR record)
    2. mDNS via avahi-resolve (common on Linux/Mac home networks)
    3. NetBIOS name (Windows hosts)
    Returns empty string if all fail.
    """
    import socket
    import subprocess

    # 1. Reverse DNS (bounded timeout to avoid long resolver stalls)
    try:
        import concurrent.futures as _cf
        with _cf.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(socket.gethostbyaddr, ip)
            try:
                name = fut.result(timeout=1.5)[0]
            except _cf.TimeoutError:
                name = ""
        if name and name != ip:
            return name.split(".")[0]   # strip domain, keep short name
    except (socket.herror, socket.gaierror, OSError, Exception):
        pass

    # 2. mDNS via avahi-resolve (if avahi-utils installed)
    try:
        result = subprocess.run(
            ["avahi-resolve", "--address", ip],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0 and result.stdout.strip():
            # output: "192.168.86.5	hostname.local"
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                name = parts[-1].rstrip(".")
                return name.replace(".local", "")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # 3. NetBIOS name via nmblookup (if samba-common installed)
    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("Looking") and "<00>" in line:
                    name = line.split()[0].strip()
                    if name and name != ip:
                        return name
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return ""

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DB_PATH   = Path(__file__).parent.parent / "data" / "surveytrace.db"
DATA_DIR  = Path(__file__).parent.parent / "data"
OUI_MAP_PATH = DATA_DIR / "oui_map.json"
WEBFP_RULES_PATH = DATA_DIR / "webfp_rules.json"
POLL_SECS = 5          # how often to check for new jobs
LOG_LEVEL = logging.INFO

# Safe port list — only these ports are touched in banner phase
SAFE_PORTS = sorted(set([
    # Standard
    21, 22, 23, 25, 53, 80, 81, 110, 143, 161, 443, 445, 465, 587, 631,
    # Databases
    1433, 1521, 3306, 5432, 5984, 6379, 7474, 9042, 9200, 27017,
    # Virtualization / containers
    902, 903, 2375, 2376, 8006, 8007, 9443, 10250,
    # Remote access
    3389, 5900, 5985, 5986,
    # VoIP
    5060, 5061,
    # IoT / home automation
    1194, 1880, 1883, 8123, 8883,
    # Dashboards and monitoring
    3000, 3001, 3030, 3100, 8384, 9090, 9091, 9093,
    # Media servers
    7878, 8096, 8920, 8989, 9117, 32400, 34401,
    # Self-hosted infrastructure
    5080, 5341, 7070,
    8000, 8001, 8080, 8081, 8082, 8086, 8088, 8089,
    8101, 8181, 8191, 8383, 8443, 8448, 8888,
    9000, 9001, 9925,
    # NAS
    5000, 5001,
    # Splunk
    8000, 8088, 8089, 8191, 9997,
    # Printers
    9100,
    # OT safe reads only
    102, 502, 4840, 20000, 44818,
]))

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(Path(__file__).parent.parent / "data" / "daemon.log"),
    ],
)
log = logging.getLogger("surveytrace")

# Runtime web fingerprint rules synced by sync_webfp.py
EXTERNAL_WEBFP_RULES: list[tuple[str, str, str]] = []  # (pattern, category, name)


def load_external_webfp_rules(path: Path) -> int:
    """
    Load synced web fingerprint rules:
      {"rules":[{"pattern":"...","category":"srv","name":"Tech"}, ...]}
    """
    global EXTERNAL_WEBFP_RULES
    if not path.exists():
        EXTERNAL_WEBFP_RULES = []
        return 0
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        rows = doc.get("rules", []) if isinstance(doc, dict) else []
        parsed: list[tuple[str, str, str]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            pat = str(row.get("pattern") or "").strip()
            cat = str(row.get("category") or "srv").strip()
            name = str(row.get("name") or "").strip()
            if len(pat) < 3 or len(pat) > 260:
                continue
            if cat not in {"srv", "net", "iot", "ws", "prn", "voi", "hv", "ot"}:
                cat = "srv"
            parsed.append((pat, cat, name if name else "Web App"))
        EXTERNAL_WEBFP_RULES = parsed
        return len(parsed)
    except Exception as e:
        log.warning("Could not load external webfp rules: %s", e)
        EXTERNAL_WEBFP_RULES = []
        return 0


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
# Commit every N rows inside one `with db_conn()` so SQLite releases the writer
# between batches (WAL still allows only one writer, but duration drops sharply).
_BULK_WRITE_COMMIT_INTERVAL = 100


@contextmanager
def db_conn() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _load_extra_safe_ports() -> list[int]:
    """
    Load optional comma/space-separated extra safe ports from config.extra_safe_ports.
    Returns sorted deduped valid ports in [1, 65535].
    """
    try:
        with db_conn() as conn:
            row = conn.execute(
                "SELECT value FROM config WHERE key='extra_safe_ports'"
            ).fetchone()
    except Exception:
        return []
    raw = str(row["value"] if row and row["value"] is not None else "").strip()
    if not raw:
        return []
    out: set[int] = set()
    for tok in re.split(r"[\s,]+", raw):
        tok = tok.strip()
        if not tok or not tok.isdigit():
            continue
        p = int(tok)
        if 1 <= p <= 65535:
            out.add(p)
    return sorted(out)


def _load_ai_enrichment_settings() -> dict[str, object]:
    """
    Load AI enrichment settings from config with safe defaults.
    """
    defaults: dict[str, str] = {
        "ai_enrichment_enabled": "0",
        "ai_provider": "ollama",
        "ai_model": "phi3:mini",
        "ai_timeout_ms": "700",
        "ai_max_hosts_per_scan": "40",
        "ai_ambiguous_only": "1",
        "ai_suggest_only": "0",
        "ai_conflict_only": "1",
        "ai_conf_threshold": "0.72",
        "ai_conf_threshold_net_srv": "0.82",
        "ai_operator_ollama_num_predict": "768",
        "ai_operator_ollama_temperature": "0.25",
        "ai_operator_ollama_num_thread": "0",
        "ai_operator_ollama_num_ctx": "0",
        "ai_openai_api_key": "",
        "ai_anthropic_api_key": "",
        "ai_gemini_api_key": "",
        "ai_openwebui_base_url": "",
        "ai_openwebui_api_key": "",
    }
    vals = dict(defaults)
    try:
        with db_conn() as conn:
            rows = conn.execute(
                "SELECT key, value FROM config WHERE key IN ("
                "'ai_enrichment_enabled','ai_provider','ai_model',"
                "'ai_timeout_ms','ai_max_hosts_per_scan','ai_ambiguous_only',"
                "'ai_suggest_only','ai_conflict_only','ai_conf_threshold','ai_conf_threshold_net_srv',"
                "'ai_operator_ollama_num_predict','ai_operator_ollama_temperature',"
                "'ai_operator_ollama_num_thread','ai_operator_ollama_num_ctx',"
                "'ai_openai_api_key','ai_anthropic_api_key','ai_gemini_api_key',"
                "'ai_openwebui_base_url','ai_openwebui_api_key'"
                ")"
            ).fetchall()
        for r in rows:
            k = str(r["key"] or "")
            if k in vals:
                vals[k] = str(r["value"] or "")
    except Exception:
        pass

    enabled = vals["ai_enrichment_enabled"] == "1"
    provider = (vals["ai_provider"] or "ollama").strip().lower()
    model = (vals.get("ai_model") or "").strip()
    if not model:
        model = {
            "openai": "gpt-4o-mini",
            "anthropic": "claude-3-5-haiku-20241022",
            "google": "gemini-2.0-flash",
            "openwebui": "llama3.2",
        }.get(provider, "phi3:mini")
    try:
        timeout_ms = int(vals["ai_timeout_ms"] or "700")
    except ValueError:
        timeout_ms = 700
    timeout_ms = max(100, min(5000, timeout_ms))
    try:
        max_hosts = int(vals["ai_max_hosts_per_scan"] or "40")
    except ValueError:
        max_hosts = 40
    max_hosts = max(1, min(5000, max_hosts))
    ambiguous_only = vals["ai_ambiguous_only"] != "0"
    suggest_only = vals["ai_suggest_only"] == "1"
    conflict_only = vals["ai_conflict_only"] != "0"
    try:
        conf_threshold = float(vals["ai_conf_threshold"] or "0.72")
    except ValueError:
        conf_threshold = 0.72
    conf_threshold = max(0.50, min(0.99, conf_threshold))
    try:
        conf_threshold_net_srv = float(vals["ai_conf_threshold_net_srv"] or "0.82")
    except ValueError:
        conf_threshold_net_srv = 0.82
    conf_threshold_net_srv = max(0.50, min(0.99, conf_threshold_net_srv))

    openai_key = (os.environ.get("OPENAI_API_KEY") or "").strip() or str(vals.get("ai_openai_api_key") or "").strip()
    anthropic_key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip() or str(vals.get("ai_anthropic_api_key") or "").strip()
    gemini_key = (
        (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or "").strip()
        or str(vals.get("ai_gemini_api_key") or "").strip()
    )
    openwebui_base = (
        (os.environ.get("OPENWEBUI_BASE_URL") or "").strip().rstrip("/")
        or str(vals.get("ai_openwebui_base_url") or "").strip().rstrip("/")
    )
    openwebui_key = (os.environ.get("OPENWEBUI_API_KEY") or "").strip() or str(
        vals.get("ai_openwebui_api_key") or ""
    ).strip()

    ollama_api_timeout = max(0.2, min(3.0, float(timeout_ms) / 1000.0))
    ollama_api_reachable = _ollama_api_tags(timeout_s=ollama_api_timeout) is not None

    availability_reason = ""
    available = False
    if not enabled:
        availability_reason = "ai_disabled"
    elif provider not in ("ollama", "openai", "anthropic", "google", "openwebui"):
        availability_reason = "unsupported_provider"
    elif provider == "ollama":
        if not ollama_api_reachable:
            availability_reason = "runtime_unreachable"
        else:
            available = True
    elif provider == "openai" and not openai_key:
        availability_reason = "missing_api_key"
    elif provider == "anthropic" and not anthropic_key:
        availability_reason = "missing_api_key"
    elif provider == "google" and not gemini_key:
        availability_reason = "missing_api_key"
    elif provider == "openwebui" and not _openwebui_base_ok(openwebui_base):
        availability_reason = "missing_or_invalid_openwebui_base_url"
    elif provider == "openwebui" and not openwebui_key:
        availability_reason = "missing_api_key"
    else:
        available = True
    try:
        num_predict = int(vals.get("ai_operator_ollama_num_predict", "768") or "768")
    except ValueError:
        num_predict = 768
    num_predict = max(0, min(8192, num_predict))
    try:
        ollama_temperature = float(vals.get("ai_operator_ollama_temperature", "0.25") or "0.25")
    except ValueError:
        ollama_temperature = 0.25
    ollama_temperature = max(0.0, min(2.0, ollama_temperature))
    try:
        num_thread = int(vals.get("ai_operator_ollama_num_thread", "0") or "0")
    except ValueError:
        num_thread = 0
    num_thread = max(0, min(256, num_thread))
    try:
        num_ctx = int(vals.get("ai_operator_ollama_num_ctx", "0") or "0")
    except ValueError:
        num_ctx = 0
    num_ctx = max(0, min(131072, num_ctx))
    if num_ctx != 0 and num_ctx < 512:
        num_ctx = 0

    ollama_generate_options: dict[str, int | float] = {}
    if num_predict > 0:
        ollama_generate_options["num_predict"] = num_predict
    ollama_generate_options["temperature"] = ollama_temperature
    if num_thread > 0:
        ollama_generate_options["num_thread"] = num_thread
    if num_ctx >= 512:
        ollama_generate_options["num_ctx"] = num_ctx
    return {
        "enabled": enabled,
        "provider": provider,
        "model": model,
        "timeout_ms": timeout_ms,
        "max_hosts_per_scan": max_hosts,
        "ambiguous_only": ambiguous_only,
        "suggest_only": suggest_only,
        "conflict_only": conflict_only,
        "conf_threshold": conf_threshold,
        "conf_threshold_net_srv": conf_threshold_net_srv,
        "available": available,
        "availability_reason": availability_reason,
        "ollama_generate_options": ollama_generate_options,
        "openai_api_key": openai_key,
        "anthropic_api_key": anthropic_key,
        "gemini_api_key": gemini_key,
        "openwebui_base_url": openwebui_base,
        "openwebui_api_key": openwebui_key,
    }


def _ollama_api_tags(timeout_s: float = 1.5) -> list[str] | None:
    """
    Return installed model tags from Ollama API, or None when runtime is unreachable.
    """
    req = urllib.request.Request("http://127.0.0.1:11434/api/tags", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            payload = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None
    try:
        doc = json.loads(payload)
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    rows = doc.get("models")
    if not isinstance(rows, list):
        return []
    names: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        if name:
            names.append(name)
    return sorted(set(names))


def _run_ollama_generate(
    model: str,
    prompt: str,
    timeout_s: float,
    ollama_options: dict[str, object] | None = None,
) -> tuple[str, str]:
    """
    Return (response_text, error). error is empty string on success.
    """
    body: dict[str, object] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }
    if ollama_options:
        body["options"] = ollama_options
    req = urllib.request.Request(
        "http://127.0.0.1:11434/api/generate",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            payload = resp.read().decode("utf-8", errors="replace")
    except TimeoutError:
        return "", "timeout"
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", errors="replace")
        except Exception:
            detail = ""
        return "", f"http_{e.code}:{detail[:120]}"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return "", f"api_unreachable:{str(e)[:120]}"
    try:
        doc = json.loads(payload)
    except Exception:
        return "", "bad_json"
    if not isinstance(doc, dict):
        return "", "bad_shape"
    out = str(doc.get("response") or "").strip()
    if out == "":
        return "", "empty_response"
    return out, ""


def _ai_gate_reason(
    ai_cfg: dict[str, object],
    fp: dict,
    ports: list[int],
    banners: dict[str, str],
    hostname: str,
    ai_attempts: int,
) -> str:
    if not bool(ai_cfg.get("available")):
        return str(ai_cfg.get("availability_reason") or "runtime_unreachable")
    if ai_attempts >= int(ai_cfg.get("max_hosts_per_scan") or 0):
        return "max_hosts_reached"
    if not ports and not banners and not hostname:
        return "no_signal"
    cat = str(fp.get("category") or "unk")
    if bool(ai_cfg.get("ambiguous_only", True)):
        return "" if cat in {"unk", "net", "srv"} else "not_ambiguous"
    return ""


def _run_ai_enrichment_ollama(
    ai_cfg: dict[str, object],
    fp: dict,
    hostname: str,
    ports: list[int],
    banners: dict[str, str],
) -> tuple[dict, str]:
    """
    Return (parsed_json, error). parsed_json is empty dict on failure.
    """
    model = str(ai_cfg.get("model") or "phi3:mini")
    timeout_s = max(0.2, float(int(ai_cfg.get("timeout_ms") or 700)) / 1000.0)
    top_ports = sorted({int(p) for p in ports if isinstance(p, int) or str(p).isdigit()})[:24]
    banner_pairs: list[str] = []
    for k, v in list(banners.items())[:8]:
        ks = str(k)
        vs = str(v or "").strip().replace("\n", " ")[:180]
        if vs:
            banner_pairs.append(f"{ks}:{vs}")
    prompt = (
        "Classify this network host for inventory enrichment.\n"
        "Allowed categories: srv, ws, net, iot, prn, hv, ot, voi, unk.\n"
        "Use evidence only; prefer unk when uncertain.\n"
        "Return ONLY JSON with keys: category, confidence, rationale.\n\n"
        f"Current category: {fp.get('category','unk')}\n"
        f"Hostname: {hostname or ''}\n"
        f"Open ports: {top_ports}\n"
        f"Banners: {banner_pairs}\n"
    )
    opts = ai_cfg.get("ollama_generate_options")
    ollama_opts = opts if isinstance(opts, dict) else None
    prov = str(ai_cfg.get("provider") or "ollama").lower()
    if prov in ("openai", "anthropic", "google", "openwebui"):
        np = 768
        if isinstance(ollama_opts, dict) and ollama_opts.get("num_predict"):
            try:
                np = int(ollama_opts["num_predict"])
            except (TypeError, ValueError):
                np = 768
        temp_f = 0.25
        if isinstance(ollama_opts, dict) and "temperature" in ollama_opts:
            try:
                temp_f = float(ollama_opts["temperature"])
            except (TypeError, ValueError):
                temp_f = 0.25
        out, err = cloud_chat_completion(
            prov,
            model,
            prompt,
            timeout_s,
            temp_f,
            np,
            str(ai_cfg.get("openai_api_key") or ""),
            str(ai_cfg.get("anthropic_api_key") or ""),
            str(ai_cfg.get("gemini_api_key") or ""),
            str(ai_cfg.get("openwebui_base_url") or ""),
            str(ai_cfg.get("openwebui_api_key") or ""),
        )
    else:
        out, err = _run_ollama_generate(
            model=model, prompt=prompt, timeout_s=timeout_s, ollama_options=ollama_opts
        )
    if err:
        return {}, err
    m = re.search(r"\{.*\}", out, re.S)
    if not m:
        return {}, "no_json"
    try:
        doc = json.loads(m.group(0))
    except Exception:
        return {}, "bad_json"
    return doc if isinstance(doc, dict) else {}, ""


def _run_ai_scan_summary_ollama(ai_cfg: dict[str, object], summary: dict) -> tuple[dict, str]:
    """
    Build an executive summary for a completed scan.
    Returns (doc, err); doc keys: overview, concerns[], next_steps[].
    """
    model = str(ai_cfg.get("model") or "phi3:mini")
    # Scan-wide summary needs more wall time than per-host calls; scale from settings with sane bounds.
    timeout_s = max(5.0, min(90.0, float(int(ai_cfg.get("timeout_ms") or 700)) / 1000.0 * 8.0))
    compact = {
        "profile": summary.get("profile"),
        "scan_mode": summary.get("scan_mode"),
        "target_cidr": summary.get("target_cidr"),
        "assets_catalogued": summary.get("assets_catalogued", 0),
        "hosts_found": summary.get("hosts_found", 0),
        "open_findings": summary.get("open_findings", 0),
        "severity_breakdown": summary.get("severity_breakdown", {}),
        "categories": summary.get("categories", {}),
        "top_ports": summary.get("top_ports", []),
        "ai_enrichment_attempts": summary.get("ai_enrichment_attempts", 0),
        "ai_enrichment_applied": summary.get("ai_enrichment_applied", 0),
        "routed_net_overrides": summary.get("routed_net_overrides", 0),
    }
    prompt = (
        "You are writing an operator summary for a network scan.\n"
        "Return ONLY JSON with keys: overview (string), concerns (array of <=5 strings), "
        "next_steps (array of <=5 strings).\n"
        "Be concise, practical, and avoid alarmist language.\n\n"
        f"Scan data JSON:\n{json.dumps(compact, ensure_ascii=False)}\n"
    )
    opts2 = ai_cfg.get("ollama_generate_options")
    ollama_opts2 = opts2 if isinstance(opts2, dict) else None
    prov2 = str(ai_cfg.get("provider") or "ollama").lower()
    if prov2 in ("openai", "anthropic", "google", "openwebui"):
        np2 = 768
        if isinstance(ollama_opts2, dict) and ollama_opts2.get("num_predict"):
            try:
                np2 = int(ollama_opts2["num_predict"])
            except (TypeError, ValueError):
                np2 = 768
        temp2 = 0.25
        if isinstance(ollama_opts2, dict) and "temperature" in ollama_opts2:
            try:
                temp2 = float(ollama_opts2["temperature"])
            except (TypeError, ValueError):
                temp2 = 0.25
        out, err = cloud_chat_completion(
            prov2,
            model,
            prompt,
            timeout_s,
            temp2,
            np2,
            str(ai_cfg.get("openai_api_key") or ""),
            str(ai_cfg.get("anthropic_api_key") or ""),
            str(ai_cfg.get("gemini_api_key") or ""),
            str(ai_cfg.get("openwebui_base_url") or ""),
            str(ai_cfg.get("openwebui_api_key") or ""),
        )
    else:
        out, err = _run_ollama_generate(
            model=model, prompt=prompt, timeout_s=timeout_s, ollama_options=ollama_opts2
        )
    if err:
        return {}, err
    m = re.search(r"\{.*\}", out, re.S)
    if not m:
        return {}, "no_json"
    try:
        doc = json.loads(m.group(0))
    except Exception:
        return {}, "bad_json"
    if not isinstance(doc, dict):
        return {}, "bad_shape"
    overview = str(doc.get("overview") or "").strip()
    concerns = [str(x).strip() for x in (doc.get("concerns") or []) if str(x).strip()]
    next_steps = [str(x).strip() for x in (doc.get("next_steps") or []) if str(x).strip()]
    if not overview and not concerns and not next_steps:
        return {}, "empty"
    return {
        "overview": overview[:600],
        "concerns": concerns[:5],
        "next_steps": next_steps[:5],
    }, ""


def log_event(conn: sqlite3.Connection, job_id: int, level: str, message: str, ip: str = "") -> None:
    conn.execute(
        "INSERT INTO scan_log (job_id, level, ip, message) VALUES (?,?,?,?)",
        (job_id, level, ip, message),
    )
    log.log(getattr(logging, level, logging.INFO), "[job %d] %s %s", job_id, ip, message)


def is_aborted(job_id: int) -> bool:
    """Check if a job has been marked aborted by the web UI."""
    try:
        with db_conn() as conn:
            row = conn.execute(
                "SELECT status FROM scan_jobs WHERE id = ?", (job_id,)
            ).fetchone()
            return row is not None and row["status"] == "aborted"
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Phase 1 — Passive discovery
# ---------------------------------------------------------------------------
def phase_passive(job_id: int, target_cidr: str, timeout_secs: int = 30) -> tuple[set[str], dict[str, set[str]], dict[str, set[str]]]:
    """
    Sniff ARP, mDNS, LLMNR/NBNS, SSDP, and IPv6 NDP traffic to discover hosts
    without sending probes.
    Returns:
      - discovered IPv4 hosts
      - passive signal tags by IPv4 host
      - observed IPv6 addresses keyed by normalized MAC (from NDP frames)
    Also stores passive hints in DB for fingerprint enrichment.
    """
    discovered: set[str] = set()
    passive_signals: dict[str, set[str]] = {}
    ndp_ipv6_by_mac: dict[str, set[str]] = {}
    if not HAS_SCAPY:
        return discovered, passive_signals, ndp_ipv6_by_mac

    network = ipaddress.ip_network(target_cidr, strict=False)

    # mDNS service type → (category, vendor_hint)
    MDNS_SERVICE_HINTS: dict[str, tuple[str, str]] = {
        "_apple-mobdev2._tcp": ("ws",  "Apple"),       # iPhone/iPad
        "_apple-pairable._tcp":("iot", "Apple"),        # Apple Watch
        "_companion-link._tcp":("ws",  "Apple"),        # Apple device
        "_homekit._tcp":       ("iot", "Apple HomeKit"),
        "_airplay._tcp":       ("iot", "Apple"),        # Apple TV / AirPlay
        "_raop._tcp":          ("iot", "Apple"),        # AirPlay audio
        "_sleep-proxy._udp":   ("ws",  "Apple"),
        "_ipp._tcp":           ("prn", "Printer"),      # IPP printer
        "_ipps._tcp":          ("prn", "Printer"),
        "_pdl-datastream._tcp":("prn", "Printer"),
        "_printer._tcp":       ("prn", "Printer"),
        "_scanner._tcp":       ("prn", "Printer"),
        "_http._tcp":          ("srv", ""),             # Generic HTTP service
        "_https._tcp":         ("srv", ""),
        "_smb._tcp":           ("srv", ""),             # SMB file share
        "_afpovertcp._tcp":    ("srv", "Apple"),        # AFP (Mac file share)
        "_nfs._tcp":           ("srv", ""),
        "_ssh._tcp":           ("srv", ""),
        "_sftp-ssh._tcp":      ("srv", ""),
        "_hap._tcp":           ("iot", "Apple HomeKit"),
        "_googlecast._tcp":    ("iot", "Google"),       # Chromecast
        "_spotify-connect._tcp":("iot","Spotify"),
        "_sonos._tcp":         ("iot", "Sonos"),
        "_roku:ecp._tcp":      ("iot", "Roku"),
        "_amzn-alexa._tcp":    ("iot", "Amazon"),
        "_home-assistant._tcp":("iot", "Home Assistant"),
        "_esphomelib._tcp":    ("iot", "ESPHome"),
        "_mqtt._tcp":          ("iot", ""),
        "_workstation._tcp":   ("ws",  ""),
        "_presence._tcp":      ("ws",  ""),
    }

    # Shared storage for passive hints discovered during sniff
    mdns_hints: dict[str, dict] = {}  # {ip: {service_type: hint}}
    llmnr_hints: dict[str, str] = {}  # {ip: hostname}
    nbns_hints: dict[str, str] = {}   # {ip: hostname}
    ssdp_hints: dict[str, tuple[str, str]] = {}  # {ip: (category, vendor)}
    ndp_seen: set[str] = set()  # IPv6 addresses observed in NDP frames

    def mark_sig(ip: str, tag: str) -> None:
        if ip not in passive_signals:
            passive_signals[ip] = set()
        passive_signals[ip].add(tag)

    def parse_ssdp_hint(payload: str) -> tuple[str, str]:
        p = payload.lower()
        if "roku" in p:
            return ("iot", "Roku")
        if "sonos" in p:
            return ("iot", "Sonos")
        if "google" in p or "chromecast" in p:
            return ("iot", "Google")
        if "samsung" in p or "lg " in p:
            return ("iot", "")
        if "upnp:rootdevice" in p:
            return ("iot", "")
        return ("", "")

    def handle_pkt(pkt):
        src = None
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            src = pkt[ARP].psrc
            if src:
                mark_sig(src, "arp")
        elif pkt.haslayer(DNS) and pkt.haslayer("IP"):
            src = pkt["IP"].src
            udp = pkt.getlayer("UDP")
            sport = int(getattr(udp, "sport", 0) or 0) if udp else 0
            dport = int(getattr(udp, "dport", 0) or 0) if udp else 0

            # Try to extract service type from mDNS PTR records (udp/5353)
            try:
                dns = pkt[DNS]
                if sport == 5353 or dport == 5353:
                    mark_sig(src, "mdns")
                    rr = dns.an
                    for _ in range(int(getattr(dns, "ancount", 0) or 0)):
                        if rr and hasattr(rr, "rrname"):
                            name = rr.rrname.decode("utf-8", errors="ignore") if isinstance(rr.rrname, bytes) else str(rr.rrname)
                            for svc, hint in MDNS_SERVICE_HINTS.items():
                                if svc in name.lower():
                                    if src not in mdns_hints:
                                        mdns_hints[src] = {}
                                    mdns_hints[src][svc] = hint
                        rr = getattr(rr, "payload", None)

                # LLMNR also uses DNS format on udp/5355
                if sport == 5355 or dport == 5355:
                    mark_sig(src, "llmnr")
                    qd = getattr(dns, "qd", None)
                    qname = ""
                    if qd is not None and hasattr(qd, "qname"):
                        qname = qd.qname.decode("utf-8", errors="ignore") if isinstance(qd.qname, bytes) else str(qd.qname)
                    host = (qname or "").strip(".").split(".", 1)[0]
                    if host and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", host):
                        llmnr_hints[src] = host
            except Exception:
                pass
        elif pkt.haslayer("IP") and pkt.haslayer("UDP"):
            src = pkt["IP"].src
            udp = pkt.getlayer("UDP")
            sport = int(getattr(udp, "sport", 0) or 0) if udp else 0
            dport = int(getattr(udp, "dport", 0) or 0) if udp else 0
            # NBNS/NetBIOS name service traffic (udp/137). Parsing payload into a
            # reliable hostname is noisy across vendors; record as passive signal.
            if sport == 137 or dport == 137:
                mark_sig(src, "nbns")
            # SSDP/UPnP multicast (udp/1900) with vendor/service hints.
            if sport == 1900 or dport == 1900:
                mark_sig(src, "ssdp")
                try:
                    raw = pkt.getlayer("Raw")
                    blob = bytes(getattr(raw, "load", b"")) if raw is not None else b""
                    text = blob.decode("utf-8", errors="ignore")
                    cat, vendor = parse_ssdp_hint(text)
                    if cat or vendor:
                        ssdp_hints[src] = (cat, vendor)
                except Exception:
                    pass
        elif pkt.haslayer("IPv6"):
            try:
                src6 = str(pkt["IPv6"].src or "")
                if src6 and not src6.startswith("fe80:"):
                    ndp_seen.add(src6)
                    macn = ""
                    if pkt.haslayer(Ether):
                        macn = _norm_mac(str(pkt[Ether].src or ""))
                    if macn:
                        if macn not in ndp_ipv6_by_mac:
                            ndp_ipv6_by_mac[macn] = set()
                        ndp_ipv6_by_mac[macn].add(src6)
            except Exception:
                pass

        if src:
            try:
                if ipaddress.ip_address(src) in network:
                    discovered.add(src)
            except ValueError:
                pass

    try:
        sniff(
            filter="arp or icmp6 or (udp and (port 5353 or port 5355 or port 137 or port 1900))",
            prn=handle_pkt,
            timeout=timeout_secs,
            store=False,
        )
    except PermissionError:
        pass

    # Store passive hints in DB for use during fingerprinting
    if mdns_hints or llmnr_hints or nbns_hints or ssdp_hints:
        with db_conn() as conn:
            for ip, hints in mdns_hints.items():
                for svc, (cat, vendor) in hints.items():
                    # Only update if currently unknown
                    row = conn.execute(
                        "SELECT category, vendor FROM assets WHERE ip=?", (ip,)
                    ).fetchone()
                    if row and row["category"] == "unk":
                        if cat:
                            conn.execute(
                                "UPDATE assets SET category=? WHERE ip=? AND category='unk'",
                                (cat, ip)
                            )
                        if vendor:
                            conn.execute(
                                "UPDATE assets SET vendor=? WHERE ip=? AND (vendor IS NULL OR vendor='')",
                                (vendor, ip)
                            )
            for ip, host in llmnr_hints.items():
                conn.execute(
                    "UPDATE assets SET hostname=? WHERE ip=? AND (hostname IS NULL OR hostname='')",
                    (host, ip),
                )
            # Keep separate source tag from LLMNR where no concrete hostname was parsed.
            for ip, host in nbns_hints.items():
                if host:
                    conn.execute(
                        "UPDATE assets SET hostname=? WHERE ip=? AND (hostname IS NULL OR hostname='')",
                        (host, ip),
                    )
            for ip, (cat, vendor) in ssdp_hints.items():
                if cat:
                    conn.execute(
                        "UPDATE assets SET category=? WHERE ip=? AND category='unk'",
                        (cat, ip),
                    )
                if vendor:
                    conn.execute(
                        "UPDATE assets SET vendor=? WHERE ip=? AND (vendor IS NULL OR vendor='')",
                        (vendor, ip),
                    )

    with db_conn() as conn:
        log_event(conn, job_id, "INFO",
                  f"Passive phase: {len(discovered)} IPv4 hosts observed "
                  f"(mDNS={len([1 for v in passive_signals.values() if 'mdns' in v])}, "
                  f"LLMNR={len([1 for v in passive_signals.values() if 'llmnr' in v])}, "
                  f"NBNS={len([1 for v in passive_signals.values() if 'nbns' in v])}, "
                  f"SSDP={len([1 for v in passive_signals.values() if 'ssdp' in v])}, "
                  f"NDPv6_sources={len(ndp_seen)})")

    return discovered, passive_signals, ndp_ipv6_by_mac


# ---------------------------------------------------------------------------
# Phase 2 - Host discovery (ARP / ping scan / force mode)
# ---------------------------------------------------------------------------
# scan_mode values:
#   auto   - same-subnet uses ARP, routed subnets use ICMP/TCP ping scan
#   routed - force ICMP/TCP ping scan, skip ARP (cross-router targets)
#   force  - -Pn mode, enumerate all IPs regardless of ping (firewalled hosts)
# ---------------------------------------------------------------------------

def _is_same_subnet(cidr: str) -> bool:
    """Check if target CIDR is on same L2 segment using routing table."""
    import subprocess
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        result  = subprocess.run(
            ["ip", "route", "get", str(next(network.hosts()))],
            capture_output=True, text=True, timeout=3
        )
        return "via" not in result.stdout
    except Exception:
        return False


def phase_discovery(
    job_id: int,
    cidrs: list[str],
    excludes: set[str],
    rate_pps: int,
    scan_mode: str = "auto",
) -> dict[str, str]:
    """
    Unified host discovery. Returns {ip: mac} where mac may be empty.

    scan_mode auto:
      - Same-subnet /24 or smaller: ARP sweep (fast, gets MACs)
      - Same-subnet larger or routed: nmap ping scan (ICMP + TCP SYN/ACK)
    scan_mode routed:
      - Always use nmap ping scan, skip ARP entirely
      - Use when scanning across routers
    scan_mode force:
      - Skip ping entirely (-Pn), enumerate all IPs as alive
      - Use when hosts are firewalled (e.g. UFW blocking ICMP)
    """
    alive: dict[str, str] = {}
    if not HAS_NMAP:
        return alive

    for cidr in cidrs:
        network     = ipaddress.ip_network(cidr, strict=False)
        same_layer2 = _is_same_subnet(cidr) if scan_mode == "auto" else False
        use_arp     = same_layer2 and network.num_addresses <= 256

        with db_conn() as conn:
            log_event(conn, job_id, "INFO",
                      f"Discovery: {cidr} mode={scan_mode} "
                      f"same_l2={same_layer2} arp={use_arp}")

        # ---- Force mode: enumerate all IPs, skip ping ----------------------
        if scan_mode == "force":
            for ip in network.hosts():
                ip_str = str(ip)
                if ip_str not in excludes:
                    alive[ip_str] = ""
            with db_conn() as conn:
                log_event(conn, job_id, "INFO",
                          f"Force (-Pn) {cidr}: {network.num_addresses - 2} IPs assumed alive")
            continue

        # ---- ARP sweep: same subnet, fast, gets MACs -----------------------
        if use_arp and HAS_SCAPY:
            try:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
                answered, _ = srp(pkt, timeout=2, verbose=False, retry=1)
                found = 0
                for _, rcv in answered:
                    ip  = rcv[ARP].psrc
                    mac = rcv[Ether].src
                    if ip not in excludes:
                        alive[ip] = mac
                        found += 1
                with db_conn() as conn:
                    log_event(conn, job_id, "INFO",
                              f"ARP sweep {cidr}: {found} hosts found")
                continue
            except Exception as e:
                log.warning("ARP sweep failed for %s: %s -- falling back to nmap ping", cidr, e)

        # ---- nmap ping scan: routed or large subnet or ARP fallback --------
        nm = nmap.PortScanner()
        nmap_args = (
            "-sn "                       # ping scan only, no port scan
            f"--max-rate {rate_pps * 10} "
            "--host-timeout 5s "
            "-PE "                       # ICMP echo request
            "-PP "                       # ICMP timestamp
            "-PS22,443,8000,8089 "       # TCP SYN to common ports
            "-PA80"                      # TCP ACK port 80
        )
        nm.scan(hosts=str(network), arguments=nmap_args)

        found = 0
        for host in nm.all_hosts():
            if nm[host].state() == "up" and host not in excludes:
                mac = nm[host].get("addresses", {}).get("mac", "")
                alive[host] = mac
                found += 1

        with db_conn() as conn:
            log_event(conn, job_id, "INFO",
                      f"Ping scan {cidr}: {found} hosts alive")

    with db_conn() as conn:
        log_event(conn, job_id, "INFO",
                  f"Discovery complete: {len(alive)} total hosts")

    return alive


def phase_icmp(job_id: int, cidrs: list[str], excludes: set[str],
               rate_pps: int) -> dict[str, str]:
    """Legacy wrapper - calls phase_discovery with auto mode."""
    return phase_discovery(job_id, cidrs, excludes, rate_pps, scan_mode="auto")


# ---------------------------------------------------------------------------
# Phase 3 — Port + banner probe
# ---------------------------------------------------------------------------
def phase_banner(
    job_id: int,
    hosts: list[str],
    rate_pps: int,
    inter_delay_ms: int,
    job: dict | None = None,
) -> dict[str, dict]:
    """
    Returns {ip: {ports: [...], banners: {port: text}}}
    """
    results: dict[str, dict] = {}
    if not HAS_NMAP:
        return results

    nm  = nmap.PortScanner()
    # Use profile port list if available, fall back to SAFE_PORTS
    profile_obj  = get_profile(job.get("profile", DEFAULT_PROFILE) if job else DEFAULT_PROFILE)
    scan_all_tcp = (profile_obj.name in ("full_tcp", "fast_full_tcp"))
    active_ports = profile_obj.port_list if profile_obj.port_list else SAFE_PORTS
    port_str     = "-" if scan_all_tcp else ",".join(str(p) for p in sorted(set(active_ports)))
    delay_s      = inter_delay_ms / 1000.0

    scan_mode = (job.get("scan_mode") or "auto") if job else "auto"
    routed_mode = (scan_mode == "routed")
    routed_fast_full_lite = (routed_mode and profile_obj.name == "fast_full_tcp")

    # Routed/VPN + full 65k scans often timeout before producing useful inventory.
    # For fast_full_tcp in routed mode, use a broad finite port set (must cover at
    # least standard_inventory's PORTS_STANDARD so we never "see less" than that profile).
    if routed_fast_full_lite:
        extra_ports = _load_extra_safe_ports()
        active_ports = sorted(set(SAFE_PORTS + PORTS_STANDARD + extra_ports))
        port_str = ",".join(str(p) for p in sorted(set(active_ports)))
        scan_all_tcp = False
        with db_conn() as conn:
            log_event(
                conn, job_id, "INFO",
                f"Routed fast_full_tcp: using {len(set(active_ports))} ports "
                f"(safe + standard_inventory list + {len(extra_ports)} extra) (not -p-) for reliable reachability"
            )

    # Batch sizing:
    # - full_tcp stays host-by-host (most conservative).
    # - fast_full_tcp can batch on larger target sets to improve throughput.
    # - Standard profiles can safely batch.
    if scan_all_tcp:
        if profile_obj.name == "fast_full_tcp" and len(hosts) > 32:
            chunk_size = 8
        elif profile_obj.name == "fast_full_tcp" and routed_mode and len(hosts) > 1:
            # Routed links are often high-latency/filtered; small batching improves
            # throughput without completely hiding per-host progress.
            chunk_size = 2
        else:
            chunk_size = 1
    else:
        chunk_size = 32
    total_batches = max(1, (len(hosts) + chunk_size - 1) // chunk_size)
    for i in range(0, len(hosts), chunk_size):
        chunk = hosts[i:i + chunk_size]
        targets = " ".join(chunk)
        batch_no = i // chunk_size + 1

        # Ensure rate is high enough; full TCP needs a longer timeout envelope.
        effective_rate = max(rate_pps, 50)   # floor of 50 pps on LAN
        port_count     = 65535 if scan_all_tcp else len(active_ports)
        # Keep full-tcp host timeout bounded so progress remains responsive.
        # Small fast_full_tcp scopes used to disable host-timeout entirely,
        # which allowed a single host to stall for the full python-nmap
        # guard window (900s). Use bounded envelopes instead.
        if profile_obj.name == "fast_full_tcp":
            # Dynamic timeout tiers:
            # - tiny scopes: keep high reliability
            # - medium scopes: balanced
            # - larger sweeps (/24-ish): shorter per-host cap for forward progress
            if routed_mode:
                # Routed/VPN paths: fail filtered hosts faster to avoid 3+ minute
                # stalls per host when nothing is reachable from this vantage point.
                if len(hosts) <= 8:
                    # For small confirmed-alive sets (phase 3 pass 1), keep a
                    # fuller envelope so known responders can still yield ports.
                    timeout_secs = 180
                elif len(hosts) <= 64:
                    timeout_secs = 45
                else:
                    timeout_secs = 20
            else:
                if len(hosts) <= 8:
                    timeout_secs = 180
                elif len(hosts) <= 64:
                    timeout_secs = 90
                else:
                    timeout_secs = 30
            # Full -p- scans need at least as much per-host time as full_tcp (120s).
            # Previous caps (e.g. 30s on wide jobs) left nmap incomplete vs standard_inventory.
            if scan_all_tcp:
                timeout_secs = max(timeout_secs, 120)
        elif profile_obj.name == "full_tcp" and scan_all_tcp:
            # full_tcp uses -p- + -sV; a flat 120s host-timeout routinely aborts before nmap
            # finishes on single-host /32 jobs, producing empty port lists while fingerprinting
            # still infers OS from hostname/DNS. Scale by scope; keep caps for large sweeps.
            nh = len(hosts)
            if nh <= 1:
                timeout_secs = 900
            elif nh <= 8:
                timeout_secs = 600
            elif nh <= 32:
                timeout_secs = 300
            else:
                timeout_secs = 180
        else:
            timeout_secs = 120 if scan_all_tcp else max(60, port_count * 2 + 15)

        vi = profile_obj.allow_version_intensity if profile_obj.allow_banner else 0
        host_timeout_arg = f" --host-timeout {timeout_secs}s" if timeout_secs > 0 else ""
        nmap_args = (
            "-Pn "  # hosts were already selected by discovery; skip host-discovery recheck
            f"-sV --version-intensity {vi} "
            f"-p{port_str} "
            f"--max-rate {effective_rate} "
            f"{host_timeout_arg} "
            f"--open"
        )
        with db_conn() as conn:
            log_event(conn, job_id, "INFO",
                      f"Phase 3 batch {batch_no}/{total_batches}: scanning {len(chunk)} hosts")
        # python-nmap subprocess timeout: must exceed nmap --host-timeout so the
        # subprocess is not killed mid-scan (especially full_tcp -p- on one host).
        scan_timeout = min(3600, max(timeout_secs + 120, 240))
        try:
            # python-nmap timeout guards against a hung subprocess/read.
            nm.scan(
                hosts=targets,
                arguments=nmap_args,
                timeout=scan_timeout,
            )
        except Exception as e:
            with db_conn() as conn:
                log_event(conn, job_id, "WARN",
                          f"Phase 3 batch timeout/error on {len(chunk)} hosts: {str(e)[:180]}")
            # Fallback: scan each host in this batch individually so one bad target
            # does not stall the entire job.
            for one_host in chunk:
                try:
                    one_host_timeout = min(3600, max(90, timeout_secs + 90))
                    nm.scan(
                        hosts=one_host,
                        arguments=nmap_args,
                        timeout=one_host_timeout,
                    )
                except Exception as e2:
                    with db_conn() as conn:
                        log_event(conn, job_id, "WARN",
                                  f"Phase 3 host scan failed for {one_host}: {str(e2)[:140]}")
                    continue

        # Progress heartbeat for long scans — keeps iteration visible in logs.
        # Log every 8 batches and on the final batch.
        if batch_no % 8 == 0 or batch_no == total_batches:
            processed = min(batch_no * chunk_size, len(hosts))
            with db_conn() as conn:
                log_event(conn, job_id, "INFO",
                          f"Phase 3 progress: {processed}/{len(hosts)} hosts processed")

        for host in nm.all_hosts():
            open_ports = []
            banners    = {}
            nmap_cpes  = set()

            for proto in nm[host].all_protocols():
                for port, data in nm[host][proto].items():
                    if data.get("state") == "open":
                        open_ports.append(port)

                        # Build banner string from service fields
                        svc = " ".join(filter(None, [
                            data.get("name", ""),
                            data.get("product", ""),
                            data.get("version", ""),
                            data.get("extrainfo", ""),
                        ])).strip()
                        if svc:
                            banners[str(port)] = svc

                        # Capture CPE directly from nmap if available
                        # nmap returns cpe as a string like 'cpe:/o:linux:linux_kernel'
                        cpe_val = data.get("cpe", "")
                        if cpe_val:
                            # nmap sometimes returns space-separated multiple CPEs
                            for c in cpe_val.split():
                                if c.startswith("cpe:"):
                                    nmap_cpes.add(c)

            # Try to get hostname from nmap first, then fall back to resolver
            hostname = ""
            nmap_hostnames = nm[host].get("hostnames", [])
            for h in nmap_hostnames:
                if h.get("name"):
                    hostname = h["name"].split(".")[0]
                    break
            if not hostname:
                hostname = resolve_hostname(host)
            if not hostname:
                # Proxmox web banner often includes "[node - Proxmox Virtual Environment]"
                for b in banners.values():
                    m = re.search(r"\[?\s*([A-Za-z0-9._-]+)\s*-\s*Proxmox Virtual Environment\]?", b, re.I)
                    if m:
                        hostname = m.group(1)
                        break

            results[host] = {
                "ports":     sorted(open_ports),
                "banners":   banners,
                "nmap_cpes": list(nmap_cpes),
                "hostname":  hostname,
            }

            with db_conn() as conn:
                log_event(conn, job_id, "PROBE",
                          f"ports={sorted(open_ports)} banners={list(banners.keys())} cpes={list(nmap_cpes)} hostname={hostname!r}",
                          host)

        time.sleep(delay_s)

        # Update progress counter after each batch
        scanned_so_far = len(results)
        with db_conn() as conn:
            conn.execute(
                "UPDATE scan_jobs SET hosts_scanned=? WHERE id=?",
                (scanned_so_far, job_id)
            )
            # Check for abort
            status = conn.execute(
                "SELECT status FROM scan_jobs WHERE id=?", (job_id,)
            ).fetchone()
        if status and status["status"] == "aborted":
            log.info("[job %d] Abort detected mid-banner-scan — stopping", job_id)
            break

    return results


# ---------------------------------------------------------------------------
# Phase 3b — Network enrichment (external sources)
# ---------------------------------------------------------------------------
def _parse_job_enrichment_ids(job: dict) -> list[int] | None:
    """
    Parse scan_jobs.enrichment_source_ids.
    None  → use all globally enabled sources (default).
    []    → skip enrichment entirely (handled in run_scan).
    [...] → only these enrichment_sources.id values (must be enabled).
    """
    raw = job.get("enrichment_source_ids")
    if raw is None or raw == "":
        return None
    if isinstance(raw, (bytes, memoryview)):
        raw = raw.decode()
    if isinstance(raw, str):
        try:
            arr = json.loads(raw)
        except json.JSONDecodeError:
            return None
    elif isinstance(raw, list):
        arr = raw
    else:
        return None
    if not isinstance(arr, list):
        return None
    out: list[int] = []
    for x in arr:
        try:
            out.append(int(x))
        except (TypeError, ValueError):
            continue
    return out


def phase_enrich(
    job_id: int,
    enrichment_source_ids: list[int] | None = None,
) -> dict[str, dict]:
    """
    Query all enabled enrichment sources and return a dict of
    {ip: enrichment_record} for use in asset upserts.
    Enrichment provides MAC addresses, hostnames, VLANs, and vendor data
    that the scanner alone can't get (especially across routers).

    Network I/O to external enrichment APIs must not run under an open db_conn()
    transaction — that would block the web UI and other writers for the
    duration of slow external calls.
    """
    if not HAS_ENRICHMENT:
        return {}

    # Load enabled sources — short DB transaction only
    try:
        with db_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM enrichment_sources WHERE enabled = 1 ORDER BY priority ASC"
            ).fetchall()
    except sqlite3.OperationalError:
        # Table doesn't exist yet — schema not migrated
        return {}

    if not rows:
        return {}

    row_dicts = [dict(r) for r in rows]

    if enrichment_source_ids is not None:
        allow = {int(x) for x in enrichment_source_ids}
        n_before = len(row_dicts)
        row_dicts = [r for r in row_dicts if int(r["id"]) in allow]
        if not row_dicts:
            if n_before > 0:
                with db_conn() as conn:
                    log_event(
                        conn, job_id, "INFO",
                        "Phase 3b: selected enrichment source id(s) are disabled or unknown; skipping",
                    )
            return {}

    enrichment_map: dict[str, dict] = {}   # ip or "mac:<addr>" -> best record
    source_counts: dict[str, int] = {}     # source_type -> raw records fetched
    source_applied: dict[str, int] = {}    # source_type -> unique IP records applied
    source_applied_mac: dict[str, int] = {}  # source_type -> unique MAC-only records applied

    for row in row_dicts:
        source = load_source(row)
        if not source:
            continue
        log.info("[job %d] Enrichment: querying source '%s'", job_id, row["source_type"])
        try:
            records = source.fetch_all()
            source_name = str(row["source_type"])
            source_counts[source_name] = source_counts.get(source_name, 0) + len(records)
            log.info("[job %d] Enrichment: got %d records from %s",
                     job_id, len(records), source_name)
            applied_here = 0
            applied_mac_here = 0
            for rec in records:
                ip  = rec.get("ip", "")
                mac = (rec.get("mac") or "").strip().lower()
                if ip:
                    enrichment_map[ip] = rec
                    applied_here += 1
                elif mac:
                    enrichment_map[f"mac:{mac}"] = rec
                    applied_mac_here += 1
            source_applied[source_name] = source_applied.get(source_name, 0) + applied_here
            source_applied_mac[source_name] = source_applied_mac.get(source_name, 0) + applied_mac_here
        except Exception as e:
            with db_conn() as conn:
                log_event(conn, job_id, "WARN",
                          f"Enrichment source '{row['source_type']}' error: {e}")

    log.info("[job %d] Enrichment: %d total records across all sources", job_id, len(enrichment_map))
    if source_counts:
        parts = []
        for src in sorted(source_counts.keys()):
            parts.append(
                f"{src} raw={source_counts[src]} applied_ip={source_applied.get(src, 0)} "
                f"applied_mac={source_applied_mac.get(src, 0)}"
            )
        with db_conn() as conn:
            log_event(conn, job_id, "INFO", "Enrichment source totals: " + " | ".join(parts))
    return enrichment_map



# ---------------------------------------------------------------------------
# Phase 3c — HTTP title grabbing
# ---------------------------------------------------------------------------
HTTP_TITLE_PORTS = [80, 443, 8080, 8081, 8082, 8083, 8086, 8088, 8089,
                    8006, 8007, 8096, 8123, 8181, 8384, 8443, 8888, 3000, 3001, 3030,
                    5080, 5341, 9000, 9001, 9090, 9091, 9443, 9925, 32400]

HTTP_TITLE_TIMEOUT = 3   # seconds per request
HTTP_TITLE_BATCH   = 20  # concurrent requests (using threads)

# Map of title keywords → (category, vendor/product)
TITLE_MAP: list[tuple[str, str, str]] = [
    # Infrastructure / monitoring
    (r"surveytrace",        "srv",  "SurveyTrace"),
    (r"portainer",          "srv",  "Portainer"),
    (r"uptime.?kuma",       "srv",  "Uptime Kuma"),
    (r"grafana",            "srv",  "Grafana"),
    (r"prometheus",         "srv",  "Prometheus"),
    (r"alertmanager",       "srv",  "Prometheus Alertmanager"),
    (r"netdata",            "srv",  "Netdata"),
    (r"zabbix|zabbix-server", "srv", "Zabbix"),
    (r"\bntfy\b",           "srv",  "ntfy"),
    (r"\bkasm\b",           "voi",  "Kasm Workspaces"),
    # Kasm SPA often hides product in <title> — match stable body / script markers
    (r"kasmweb|kasmtechnologies|[\"']kasm_api[\"']|/api/public/kasm",
     "voi",  "Kasm Workspaces"),
    (r"mastodon",           "srv",  "Mastodon"),
    (r"checkmk",            "srv",  "Check MK"),
    (r"librenms",           "srv",  "LibreNMS"),
    (r"prtg",               "srv",  "PRTG"),
    # Dashboards
    (r"homepage",           "srv",  "Homepage Dashboard"),
    (r"homarr",             "srv",  "Homarr"),
    (r"heimdall",           "srv",  "Heimdall"),
    (r"organizr",           "srv",  "Organizr"),
    (r"dasherr",            "srv",  "Dasherr"),
    (r"flame",              "srv",  "Flame Dashboard"),
    # Media
    (r"jellyfin",           "srv",  "Jellyfin"),
    (r"\bplex\b",           "srv",  "Plex Media Server"),
    (r"emby",               "srv",  "Emby"),
    (r"navidrome",          "srv",  "Navidrome"),
    (r"audiobookshelf",     "srv",  "Audiobookshelf"),
    # Arr stack
    (r"sonarr",             "srv",  "Sonarr"),
    (r"radarr",             "srv",  "Radarr"),
    (r"lidarr",             "srv",  "Lidarr"),
    (r"prowlarr",           "srv",  "Prowlarr"),
    (r"readarr",            "srv",  "Readarr"),
    (r"bazarr",             "srv",  "Bazarr"),
    (r"overseerr",          "srv",  "Overseerr"),
    (r"jackett",            "srv",  "Jackett"),
    # Download
    (r"qbittorrent",        "srv",  "qBittorrent"),
    (r"transmission",       "srv",  "Transmission"),
    (r"sabnzbd",            "srv",  "SABnzbd"),
    (r"nzbget",             "srv",  "NZBGet"),
    # Storage / files
    (r"nextcloud",          "srv",  "Nextcloud"),
    (r"owncloud",           "srv",  "ownCloud"),
    (r"syncthing",          "srv",  "Syncthing"),
    (r"filebrowser",        "srv",  "File Browser"),
    (r"seafile",            "srv",  "Seafile"),
    (r"minio",              "srv",  "MinIO"),
    (r"truenas",            "srv",  "TrueNAS"),
    (r"freenas",            "srv",  "TrueNAS"),
    (r"proxmox|pve\.|pve\s", "hv",  "Proxmox VE"),
    # Dev / code
    (r"gitea",              "srv",  "Gitea"),
    (r"gogs",               "srv",  "Gogs"),
    (r"gitlab",             "srv",  "GitLab"),
    (r"jenkins",            "srv",  "Jenkins"),
    (r"drone",              "srv",  "Drone CI"),
    (r"woodpecker",         "srv",  "Woodpecker CI"),
    (r"code.?server",       "srv",  "code-server"),
    (r"jupyter",            "srv",  "Jupyter"),
    # Networking
    (r"adguard",            "net",  "AdGuard Home"),
    (r"pi.?hole",           "net",  "Pi-hole"),
    (r"unifi",              "net",  "UniFi"),
    (r"opnsense",           "net",  "OPNsense"),
    (r"pfsense",            "net",  "pfSense"),
    (r"openwrt",            "net",  "OpenWrt"),
    (r"ddwrt",              "net",  "DD-WRT"),
    (r"mikrotik",           "net",  "MikroTik"),
    # Logging / observability
    (r"seq ",               "srv",  "Seq"),
    (r"openobserve",        "srv",  "OpenObserve"),
    (r"loki",               "srv",  "Grafana Loki"),
    (r"kibana",             "srv",  "Kibana"),
    (r"splunk",             "srv",  "Splunk"),
    (r"graylog",            "srv",  "Graylog"),
    # Smart home
    (r"home.?assistant",    "iot",  "Home Assistant"),
    (r"node.?red",          "iot",  "Node-RED"),
    (r"homebridge",         "iot",  "Homebridge"),
    (r"hubitat",            "iot",  "Hubitat"),
    (r"openhab",            "iot",  "openHAB"),
    # NAS / storage
    (r"synology",           "srv",  "Synology DSM"),
    (r"dsm",                "srv",  "Synology DSM"),
    (r"qnap",               "srv",  "QNAP"),
    # Misc self-hosted
    (r"bitwarden",          "srv",  "Bitwarden"),
    (r"vaultwarden",        "srv",  "Vaultwarden"),
    (r"actual",             "srv",  "Actual Budget"),
    (r"firefly",            "srv",  "Firefly III"),
    (r"immich",             "srv",  "Immich"),
    (r"photoprism",         "srv",  "PhotoPrism"),
    (r"mealie",             "srv",  "Mealie"),
    (r"paperless",          "srv",  "Paperless-ngx"),
    (r"bookstack",          "srv",  "BookStack"),
    (r"wikijs",             "srv",  "Wiki.js"),
    (r"freshrss",           "srv",  "FreshRSS"),
    (r"miniflux",           "srv",  "Miniflux"),
    (r"calibre",            "srv",  "Calibre-Web"),
    (r"kavita",             "srv",  "Kavita"),
    (r"komga",              "srv",  "Komga"),
    (r"changedetection",    "srv",  "changedetection.io"),
    (r"upsnap",             "srv",  "UpSnap"),
    (r"stirling",           "srv",  "Stirling PDF"),
    (r"it.?tools",          "srv",  "IT Tools"),
    (r"speedtest",          "srv",  "Speedtest"),
]


def _format_tls_cert_names(cert: dict | None) -> str:
    """Flatten DNS names / CN from ssl.getpeercert() dict for pattern matching."""
    if not cert:
        return ""
    names: list[str] = []
    for typ, val in cert.get("subjectAltName", ()) or ():
        if typ == "DNS" and val:
            names.append(str(val))
    for rdn in cert.get("subject", ()) or ():
        for ava in rdn:
            if len(ava) >= 2 and ava[0][0] == "commonName" and ava[0][1]:
                names.append(str(ava[0][1]))
    return " ".join(names)


def _tls_peer_names_quick(host: str, port: int, timeout: float = HTTP_TITLE_TIMEOUT) -> str:
    """TLS handshake only — used as fallback when urllib does not expose the cert."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return _format_tls_cert_names(ssock.getpeercert())
    except Exception:
        return ""


def _peer_cert_from_http_response(resp) -> str:
    """Try to read TLS peer cert names from an open urllib response (one connection)."""
    cur = getattr(resp, "fp", None)
    for _ in range(12):
        if cur is None:
            break
        if isinstance(cur, ssl.SSLSocket):
            try:
                return _format_tls_cert_names(cur.getpeercert())
            except Exception:
                return ""
        nxt = getattr(cur, "raw", None) or getattr(cur, "_sock", None)
        if nxt is cur:
            break
        cur = nxt
    return ""


def _fetch_http_snapshot(ip: str, port: int, tls: bool) -> dict[str, str | None]:
    """
    Fetch HTTP identity: title, Server / X-Powered-By, body prefix, TLS names.
    Used for generic product detection beyond <title> alone.
    """
    import urllib.request
    import re as _re

    out: dict[str, str | None] = {
        "title": None,
        "server": None,
        "powered": None,
        "body": "",
        "cert": "",
    }
    scheme = "https" if tls else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "SurveyTrace/1.0"})
        with urllib.request.urlopen(req, timeout=HTTP_TITLE_TIMEOUT,
                                    context=ctx if tls else None) as resp:
            out["server"] = resp.headers.get("Server")
            out["powered"] = resp.headers.get("X-Powered-By")
            if tls:
                out["cert"] = _peer_cert_from_http_response(resp) or ""
            raw = resp.read(12288).decode("utf-8", errors="ignore")
        out["body"] = raw[:8192]
        m = _re.search(r"<title[^>]*>(.*?)</title>", raw, _re.IGNORECASE | _re.DOTALL)
        if m:
            out["title"] = m.group(1).strip()[:200]
        if tls and not (out.get("cert") or "").strip():
            out["cert"] = _tls_peer_names_quick(ip, port) or ""
    except Exception:
        pass
    return out


def _snapshot_to_probe_line(port: int, snap: dict[str, str | None]) -> str:
    parts = [
        f"PORT{port}",
        f"TITLE={snap.get('title') or ''}",
        f"SERVER={snap.get('server') or ''}",
        f"XPB={snap.get('powered') or ''}",
        f"CERT={snap.get('cert') or ''}",
        (snap.get("body") or "")[:6000],
    ]
    return "\n".join(parts)


def _port_probe_priority(p: int) -> int:
    """Lower sorts first — prefer HTTPS app ports for merged probe."""
    order = (
        443, 8443, 9443, 8006, 8007, 8089, 8080, 8888, 3000, 3001, 9000, 9090,
        80, 8000, 8001, 8081, 8082, 8083, 8086, 8088, 8096, 8123, 8181, 8384,
        5080, 5341, 9001, 9091, 9925, 32400, 3030,
    )
    try:
        return order.index(p)
    except ValueError:
        return 500 + p


def _classify_http_probe_blob(blob: str) -> tuple[str, str] | None:
    """Run built-in + synced web fingerprint rules over merged HTTP/TLS probe text."""
    import re as _re
    if not blob or len(blob) < 8:
        return None
    for pattern, cat, product in TITLE_MAP:
        if _re.search(pattern, blob, _re.IGNORECASE):
            return cat, product
    for pattern, cat, name in EXTERNAL_WEBFP_RULES:
        try:
            if _re.search(pattern, blob, _re.IGNORECASE):
                return cat, name
        except re.error:
            continue
    return None


def _generic_web_stack_vendor(blob: str) -> str | None:
    """
    When no TITLE_MAP hit: surface HTTP Server / X-Powered-By as a weak vendor hint
    so unknown self-hosted stacks still show *some* fingerprint.
    """
    import re as _re
    if not blob or len(blob) < 12:
        return None
    srv = _re.search(r"^SERVER=(.+)$", blob, _re.MULTILINE | _re.IGNORECASE)
    xpb = _re.search(r"^XPB=(.+)$", blob, _re.MULTILINE | _re.IGNORECASE)
    bits = []
    if srv and srv.group(1).strip():
        bits.append(srv.group(1).strip()[:80])
    if xpb and xpb.group(1).strip():
        bits.append("via " + xpb.group(1).strip()[:80])
    if not bits:
        return None
    return " · ".join(bits)[:160]


def phase_http_titles(
    job_id: int,
    hosts: dict[str, dict],   # {ip: {ports: [...], banners: {...}}}
) -> tuple[dict[str, dict[int, str]], dict[str, str]]:
    """
    For each host with HTTP ports open, fetch titles + body/header/TLS hints.
    Returns (titles_by_ip, merged_probe_by_ip) for generic product detection.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    titles_out: dict[str, dict[int, str]] = {}
    snapshots: dict[str, dict[int, dict[str, str | None]]] = {}
    tasks = []  # (ip, port, tls)

    for ip, br in hosts.items():
        ports = set(br.get("ports", []))
        for port in HTTP_TITLE_PORTS:
            if port not in ports:
                continue
            tls = port in (443, 8443, 8089, 9443, 5986, 8006, 8007)
            tasks.append((ip, port, tls))

    if not tasks:
        return titles_out, {}

    with db_conn() as conn:
        log_event(conn, job_id, "INFO",
                  f"Phase 3c: HTTP probe — {len(tasks)} endpoints across {len(hosts)} hosts")

    def fetch(ip: str, port: int, tls: bool) -> tuple[str, int, dict[str, str | None]]:
        snap = _fetch_http_snapshot(ip, port, tls)
        if tls and not (snap.get("title") or snap.get("body")):
            snap = _fetch_http_snapshot(ip, port, False)
        return ip, port, snap

    with ThreadPoolExecutor(max_workers=HTTP_TITLE_BATCH) as pool:
        futures = {pool.submit(fetch, ip, port, tls): (ip, port)
                   for ip, port, tls in tasks}
        for future in as_completed(futures):
            try:
                ip, port, snap = future.result()
                snapshots.setdefault(ip, {})[port] = snap
                if snap.get("title"):
                    titles_out.setdefault(ip, {})[port] = snap["title"]  # type: ignore[index]
            except Exception:
                pass

    probes: dict[str, str] = {}
    for ip, per_port in snapshots.items():
        lines = [
            _snapshot_to_probe_line(p, s)
            for p, s in sorted(per_port.items(), key=lambda kv: _port_probe_priority(kv[0]))
        ]
        blob = "\n---\n".join(lines)
        if blob.strip():
            probes[ip] = blob

    found_t = sum(len(v) for v in titles_out.values())
    with db_conn() as conn:
        log_event(conn, job_id, "INFO",
                  f"Phase 3c: HTTP titles {found_t} / probe hosts {len(probes)} across {len(hosts)} scanned")

    return titles_out, probes


# ---------------------------------------------------------------------------
# Phase 4 — CVE correlation (SQLite NVD database)
# ---------------------------------------------------------------------------
NVD_DB_PATH = Path(__file__).parent.parent / "data" / "nvd.db"

# Minimum CPE component depth required before we'll match CVEs.
# vendor+product = 2 components minimum — prevents "cpe:/o:linux" matching
# every Linux CVE including IIS, Windows, etc.
# For version-specific CPEs (3 components) we match exactly.
CPE_MIN_DEPTH = 2   # must have at least vendor:product

# CVE publication cutoff — ignore ancient CVEs that are almost certainly
# patched or irrelevant. Overridable via UI year filter but this is the
# hard floor in the scanner itself.
CVE_MIN_YEAR = 2015


def _cpe_fragments_for_query(cpe: str) -> list[str]:
    """
    Build ordered list of CPE fragments to query, most specific first.
    Never goes below vendor+product depth to avoid false positives.

    e.g. 'cpe:/a:nginx:nginx:1.18' produces:
      ['cpe:/a:nginx:nginx:1.18', 'cpe:/a:nginx:nginx',
       'cpe:/h:nginx:nginx',      'cpe:/o:nginx:nginx']
    but NOT 'cpe:/a:nginx' (vendor-only — too broad)
    """
    parts = cpe.rstrip("*").rstrip(":").split(":")
    # parts: ['cpe', '/x', 'vendor', 'product', 'version', ...]
    vendor_parts = parts[2:]  # ['vendor', 'product', 'version', ...]

    if len(vendor_parts) < 1:
        return []

    fragments = []
    for cpe_type in ("a", "h", "o"):
        prefix = f"cpe:/{cpe_type}"
        # Start from most specific (all components) down to vendor+product minimum
        for n in range(len(vendor_parts), CPE_MIN_DEPTH - 1, -1):
            frag = prefix + ":" + ":".join(vendor_parts[:n])
            if frag not in fragments:
                fragments.append(frag)

    return fragments


def query_cves_for_cpe(cpe: str) -> list[dict]:
    """
    Query the NVD SQLite database for CVEs matching a CPE string.

    Key design decisions to avoid false positives:
    - Requires minimum vendor+product depth (no vendor-only matches)
    - Stops at the first depth level that produces results (don't broaden
      unnecessarily — if 'nginx:nginx:1.18' matches, don't also add
      everything from 'nginx:nginx')
    - Applies a minimum publication year cutoff (CVE_MIN_YEAR)
    - Caps results per asset to avoid noise floods
    """
    if not NVD_DB_PATH.exists():
        log.warning("NVD database not found at %s — run sync_nvd.py first", NVD_DB_PATH)
        return []

    fragments = _cpe_fragments_for_query(cpe)
    if not fragments:
        return []

    try:
        conn = sqlite3.connect(str(NVD_DB_PATH), timeout=10)
        conn.row_factory = sqlite3.Row
        found: dict[str, dict] = {}

        # Group fragments by depth so we can stop at first productive depth
        # depth = number of colon-separated components
        from itertools import groupby
        def depth(f: str) -> int:
            return len(f.split(":"))

        frags_by_depth: dict[int, list[str]] = {}
        for f in fragments:
            d = depth(f)
            frags_by_depth.setdefault(d, []).append(f)

        # Query from most specific (deepest) to least specific
        for d in sorted(frags_by_depth.keys(), reverse=True):
            for frag in frags_by_depth[d]:
                rows = conn.execute("""
                    SELECT c.cve_id, c.cvss, c.severity, c.description, c.published
                    FROM cpe_cve m
                    JOIN cves c ON c.cve_id = m.cve_id
                    WHERE m.cpe_fragment = ?
                      AND (
                        c.published IS NULL
                        OR c.published = ''
                        OR CAST(substr(c.published, 1, 4) AS INTEGER) >= ?
                      )
                    ORDER BY c.cvss DESC
                """, (frag, CVE_MIN_YEAR)).fetchall()

                for row in rows:
                    cve_id = row["cve_id"]
                    if cve_id not in found:
                        found[cve_id] = dict(row)

            # Stop broadening if we already found matches at this depth.
            # This prevents e.g. 'nginx:nginx' matches from also pulling in
            # everything tagged just with 'nginx' (vendor-only).
            if found:
                break

        conn.close()

        # Sort by CVSS descending, cap per asset to keep results actionable
        results = sorted(found.values(), key=lambda x: x.get("cvss", 0) or 0, reverse=True)
        return results[:30]

    except sqlite3.Error as e:
        log.error("NVD DB query error for CPE %s: %s", cpe, e)
        return []


def _extract_version(cpe: str) -> tuple[int, ...]:
    """
    Extract a comparable version tuple from a CPE string.
    e.g. 'cpe:/a:apache:http_server:2.4.66' → (2, 4, 66)
    Returns empty tuple if no version found.
    """
    import re
    parts = cpe.rstrip("*").rstrip(":").split(":")
    # Version is 4th component onwards: cpe:/a:vendor:product:version
    vp = [p for p in parts[2:] if p and p not in ("*", "-", "")]
    if len(vp) < 3:
        return ()
    ver_str = vp[2]
    # Extract numeric parts only (handles 2.4.66, 9.2p1, etc.)
    nums = re.findall(r'\d+', ver_str)
    if not nums:
        return ()
    return tuple(int(n) for n in nums[:4])


def _version_affected(cve_description: str, detected_version: tuple[int, ...]) -> bool:
    """
    Heuristic check: is our detected version within the affected range?
    Returns True if affected (or unknown), False if clearly not affected.
    Conservative — returns True when pattern can't be determined.
    """
    if not detected_version or not cve_description:
        return True

    import re

    # Pattern 1: "before X.Y.Z" / "prior to X.Y.Z" / "earlier than X.Y.Z"
    for ver_str in re.findall(
        r'(?:before|prior to|earlier than)\s+(\d+\.\d+(?:\.\d+)?)',
        cve_description, re.IGNORECASE
    ):
        nums = tuple(int(n) for n in ver_str.split(".")[:4])
        if detected_version >= nums:
            return False

    # Pattern 2: "X.Y.Z and earlier" / "X.Y.Z and prior" / "X.Y.Z or earlier"
    for ver_str in re.findall(
        r'(\d+\.\d+(?:\.\d+)?)\s+(?:and|or)\s+(?:earlier|prior|before)',
        cve_description, re.IGNORECASE
    ):
        nums = tuple(int(n) for n in ver_str.split(".")[:4])
        if detected_version > nums:
            return False

    # Pattern 3: "X.Y.Z and prior versions"
    for ver_str in re.findall(
        r'(\d+\.\d+(?:\.\d+)?)\s+(?:and|or)\s+prior\s+versions?',
        cve_description, re.IGNORECASE
    ):
        nums = tuple(int(n) for n in ver_str.split(".")[:4])
        if detected_version > nums:
            return False

    # Pattern 4: "through X.Y.Z" / "through to X.Y.Z" / "up to X.Y.Z"
    for ver_str in re.findall(
        r'(?:through\s+(?:to\s+)?|up\s+to\s+)(\d+\.\d+(?:\.\d+)?)',
        cve_description, re.IGNORECASE
    ):
        nums = tuple(int(n) for n in ver_str.split(".")[:4])
        if detected_version > nums:
            return False

    # Pattern 5: "X.Y.Z to X.Y.Z" or "X.Y.Z-X.Y.Z" (range — check upper bound)
    for lo_str, hi_str in re.findall(
        r'(\d+\.\d+(?:\.\d+)?)\s*(?:to|-)\s*(\d+\.\d+(?:\.\d+)?)',
        cve_description, re.IGNORECASE
    ):
        lo_nums = tuple(int(n) for n in lo_str.split(".")[:4])
        hi_nums = tuple(int(n) for n in hi_str.split(".")[:4])
        if lo_nums < hi_nums and detected_version > hi_nums:
            return False

    # Pattern 6: "only affects X.Y.Z" — specific version, not a range
    only_versions = re.findall(
        r'only affects?\s+(?:[A-Za-z\s]+)?(\d+\.\d+(?:\.\d+)?)',
        cve_description, re.IGNORECASE
    )
    if only_versions:
        affected_specific = [
            tuple(int(n) for n in v.split(".")[:4])
            for v in only_versions
        ]
        if detected_version not in affected_specific:
            return False

    return True  # couldn't determine — assume affected (conservative)


def _should_skip_browser_scoped_cve(description: str, check_cpe: str) -> bool:
    """
    NVD sometimes links Mozilla-browser CVEs to broad CPE fragments that also
    hit unrelated stacks (e.g. Expat issues 'affecting Firefox < 50' matched
    via python:python). Drop when the prose clearly scopes to Firefox/Thunderbird
    but the correlated CPE is not a Mozilla browser product.
    """
    cpe_l = check_cpe.lower()
    if any(
        s in cpe_l
        for s in (
            ":mozilla:firefox",
            ":mozilla:thunderbird",
            ":mozilla:seamonkey",
        )
    ):
        return False
    d = description.lower()
    needles = (
        "firefox <",
        "firefox before",
        "affects firefox",
        "mozilla firefox",
        "through firefox",
        "in firefox ",
        "thunderbird <",
        "thunderbird before",
        "affects thunderbird",
        "mozilla thunderbird",
    )
    return any(n in d for n in needles)


def _should_skip_expat_cve_on_python_cpe_only(description: str, check_cpe: str) -> bool:
    """
    Expat/libexpat CVEs correlated only from cpe:...:python:... are unreliable:
    embedded libexpat tracks its own versions, and _version_affected() may
    mis-compare CPython semver against expat bounds in the same description.
    Keep the CVE if the text clearly ties to CPython or we have an expat CPE.
    """
    cpe_l = check_cpe.lower()
    if "expat" in cpe_l or "libexpat" in cpe_l:
        return False
    if ":python:" not in cpe_l:
        return False
    d = description.lower()
    if "expat" not in d:
        return False
    if "cpython" in d or " in cpython" in d or "python's" in d:
        return False
    # Wording like "Python before 3.x" (CPython ships pyexpat/expat)
    if re.search(r"python\s+before\s+3\.", d):
        return False
    return True


def _parse_asset_ports(asset: dict) -> set[int]:
    """Return normalized open port set from asset row/dict."""
    ports_raw = asset.get("ports", [])
    if not ports_raw:
        ports_raw = asset.get("open_ports", [])
    if isinstance(ports_raw, str):
        try:
            ports_raw = json.loads(ports_raw)
        except Exception:
            ports_raw = []
    out: set[int] = set()
    for p in (ports_raw or []):
        try:
            out.add(int(p))
        except Exception:
            continue
    return out


def _asset_has_tls_surface(asset: dict) -> bool:
    """
    True if asset has plausible TLS-exposed ports.
    Used to suppress TLS-cipher CVEs (e.g. Sweet32) on non-TLS hosts.
    """
    tls_ports = {
        443, 465, 587, 636, 853, 989, 990, 993, 995,
        8443, 9443, 5986, 8006, 8007, 8089, 10443,
    }
    return bool(_parse_asset_ports(asset) & tls_ports)


def _should_skip_odoo_cve_without_odoo_cpe(description: str, check_cpe: str) -> bool:
    """Drop Odoo-scoped CVEs unless the matched CPE is explicitly Odoo."""
    d = description.lower()
    if "odoo" not in d:
        return False
    return ":odoo:" not in check_cpe.lower()


def _should_skip_sweet32_without_tls_surface(description: str, asset: dict) -> bool:
    """
    Sweet32/3DES findings are only meaningful when a TLS-like listener exists.
    """
    d = description.lower()
    is_sweet32 = (
        "sweet32" in d
        or "triple des" in d
        or (" 3des" in f" {d}")
        or "des and triple des" in d
    )
    if not is_sweet32:
        return False
    return not _asset_has_tls_surface(asset)


def phase_cve(job_id: int, assets_to_check: list[dict]) -> list[dict]:
    """
    Match CPE strings against the NVD SQLite database.
    Uses indexed queries per asset — fast regardless of database size.
    Returns list of finding dicts ready to upsert into findings table.
    """
    if not NVD_DB_PATH.exists():
        log.warning("NVD database not found — skipping CVE correlation. Run sync_nvd.py first.")
        return []

    new_findings: list[dict] = []

    # CPE types that are too broad for reliable CVE matching.
    # OS and distro CPEs match every application ever ported to that OS.
    # We only want CVEs for software we actually DETECTED on an open port.
    SKIP_CPE_VENDORS = {
        # OS / distro level — way too broad
        "linux", "canonical", "debian", "redhat", "centos", "fedora",
        "ubuntu", "suse", "opensuse", "arch", "alpine", "gentoo",
        "freebsd", "netbsd", "apple",
        "microsoft",    # windows OS CVEs — too generic
        # Generic protocol/service stubs from port profiles
        # These are port-profile guesses, not confirmed software identities
        "sip", "mqtt", "modbus", "dnp3", "ethernet_ip", "opc_ua",
        "printer", "ipp", "http_alt", "vnc",
        # openbsd is intentionally NOT skipped here: nmap frequently emits
        # legitimate app CPEs such as cpe:/a:openbsd:openssh:<ver>.
        # We already skip OS-level CPEs via cpe_type == "o" above.
        # Note: database vendors are NOT skipped — if nmap returns a
        # versioned CPE like cpe:/a:postgresql:postgresql:14.5 that is
        # legitimate. The major.minor version requirement handles
        # version-less CPEs like samba:4 or postgresql:4 (no minor).
    }

    for asset in assets_to_check:
        # Build the list of CPEs to check for this asset.
        # Priority: nmap per-port CPEs (most specific) > fingerprint CPE
        # Rule: only check CPEs for specific software with a version number,
        #       never for OS-level or generic CPEs.
        cpes_to_check: list[str] = []

        # 1. nmap per-port CPEs — these are the most reliable
        #    e.g. cpe:/a:openbsd:openssh:9.2p1 from port 22
        #    e.g. cpe:/a:apache:http_server:2.4.66
        for nmap_cpe in asset.get("nmap_cpes", []):
            parts    = nmap_cpe.rstrip("*").rstrip(":").split(":")
            cpe_type = parts[1].lstrip("/") if len(parts) > 1 else ""
            vp       = [p for p in parts[2:] if p and p not in ("*", "-", "")]
            vendor   = vp[0].lower() if vp else ""

            # Skip OS-level CPEs — they match everything on that OS
            if cpe_type == "o":
                continue
            # Skip generic/broad vendors
            if vendor in SKIP_CPE_VENDORS:
                continue
            # Require vendor + product + version with at least major.minor
            # format (e.g. "4" alone is not enough — need "4.7" or "4.7.3")
            # "samba:4" → not specific enough; "samba:4.7.3" → OK
            if len(vp) < 3:
                log.debug("Skipping version-less nmap CPE: %s", nmap_cpe)
                continue
            # Version part must contain a dot (major.minor minimum)
            version_part = vp[2] if len(vp) > 2 else ""
            if "." not in version_part:
                log.debug("Skipping major-only version CPE: %s", nmap_cpe)
                continue

            cpes_to_check.append(nmap_cpe)

        # 2. Fingerprint CPE as fallback — only if it's application-level
        #    with a specific product AND version (not OS, not generic, not version-less)
        #    Fingerprint CPEs like cpe:/h:lighttpd:lighttpd:* have no real version
        #    and would match every CVE for that product — skip them entirely.
        if not cpes_to_check:
            fp_cpe = asset.get("cpe", "")
            if fp_cpe:
                parts    = fp_cpe.rstrip("*").rstrip(":").split(":")
                cpe_type = parts[1].lstrip("/") if len(parts) > 1 else ""
                vp       = [p for p in parts[2:] if p and p not in ("*", "-", "")]
                vendor   = vp[0].lower() if vp else ""

                # Require vendor + product + version with major.minor minimum
                # Fingerprint-derived CPEs without real versions are skipped
                if len(vp) >= 3 and vendor not in SKIP_CPE_VENDORS:
                    version_part = vp[2]
                    if "." in version_part and cpe_type in ("a", "h"):
                        cpes_to_check.append(fp_cpe)
                    else:
                        log.debug("Skipping fingerprint CPE without real version: %s", fp_cpe)

        if not cpes_to_check:
            log.debug("No specific CPEs to check for %s (cpe=%s)", asset.get("ip"), asset.get("cpe"))
            continue

        # Query CVEs for each specific CPE
        all_matches: dict[str, dict] = {}
        for check_cpe in cpes_to_check:
            detected_ver = _extract_version(check_cpe)
            for m in query_cves_for_cpe(check_cpe):
                if m["cve_id"] in all_matches:
                    continue
                # Version-aware filter
                if detected_ver and not _version_affected(
                    m.get("description", ""), detected_ver
                ):
                    log.debug("Skipping %s for %s — version %s not in affected range",
                              m["cve_id"], check_cpe, detected_ver)
                    continue

                # Role-specific CVE filter: skip CVEs that require a specific
                # server role the asset almost certainly doesn't have.
                # e.g. Samba AD DC CVEs don't apply to basic file servers.
                desc = (m.get("description") or "").lower()
                asset_cat = asset.get("category", "")
                skip_roles = []
                # Samba AD DC role — only applies if running as a domain controller
                if "samba" in check_cpe.lower():
                    skip_roles = [
                        "active directory domain controller",
                        "ad dc", "samba ad", "samba 4 ad",
                        "domain controller", "kdc", "key distribution center",
                        "kpasswd", "rodc", "read-only domain controller",
                    ]
                if any(role in desc for role in skip_roles):
                    log.debug("Skipping %s — role-specific CVE not applicable to %s",
                              m["cve_id"], asset.get("ip"))
                    continue

                if _should_skip_browser_scoped_cve(m.get("description", ""), check_cpe):
                    log.debug(
                        "Skipping %s — browser-scoped CVE without Mozilla browser CPE (%s)",
                        m["cve_id"],
                        check_cpe,
                    )
                    continue

                if _should_skip_expat_cve_on_python_cpe_only(
                    m.get("description", ""), check_cpe
                ):
                    log.debug(
                        "Skipping %s — Expat CVE on python CPE only (%s)",
                        m["cve_id"],
                        check_cpe,
                    )
                    continue

                if _should_skip_odoo_cve_without_odoo_cpe(
                    m.get("description", ""), check_cpe
                ):
                    log.debug(
                        "Skipping %s — Odoo-scoped CVE without Odoo CPE (%s)",
                        m["cve_id"],
                        check_cpe,
                    )
                    continue

                if _should_skip_sweet32_without_tls_surface(
                    m.get("description", ""), asset
                ):
                    log.debug(
                        "Skipping %s — Sweet32/3DES CVE without TLS surface on asset %s",
                        m["cve_id"],
                        asset.get("ip"),
                    )
                    continue

                all_matches[m["cve_id"]] = m

        matches = sorted(all_matches.values(), key=lambda x: x.get("cvss", 0) or 0, reverse=True)[:20]

        if not matches:
            continue

        for entry in matches:
            new_findings.append({
                "asset_id":    asset["id"],
                "ip":          asset["ip"],
                "cve_id":      entry["cve_id"],
                "cvss":        entry.get("cvss", 0),
                "severity":    entry.get("severity", "info"),
                "description": entry.get("description", ""),
                "published":   entry.get("published", ""),
            })

        with db_conn() as conn:
            log_event(conn, job_id, "INFO",
                      f"CVE match: {len(matches)} CVEs for CPEs={cpes_to_check}", asset["ip"])

    return new_findings


# ---------------------------------------------------------------------------
# Device identity (see docs/DEVICE_IDENTITY.md)
# ---------------------------------------------------------------------------
def _norm_mac(m: str | None) -> str:
    s = re.sub(r"[^0-9a-fA-F]", "", (m or "")).lower()
    if len(s) == 12 and re.fullmatch(r"[0-9a-f]{12}", s):
        return s
    return ""


def _insert_device_row(conn: sqlite3.Connection, mac: str) -> int:
    macn = _norm_mac(mac)
    cur = conn.execute(
        """INSERT INTO devices (created_at, updated_at, primary_mac_norm)
           VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)""",
        (macn or None,),
    )
    return int(cur.lastrowid)


def migrate_device_identity_v1(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT value FROM config WHERE key = 'migration_device_identity_v1'"
    ).fetchone()
    if row and str(row["value"] or "") == "1":
        return False
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
            primary_mac_norm   TEXT,
            label                TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(primary_mac_norm)")
    try:
        conn.execute(
            "ALTER TABLE assets ADD COLUMN device_id INTEGER REFERENCES devices(id)"
        )
    except Exception:
        pass
    try:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_assets_device_id ON assets(device_id)"
        )
    except Exception:
        pass
    for r in conn.execute(
        "SELECT id, mac FROM assets WHERE device_id IS NULL"
    ).fetchall():
        did = _insert_device_row(conn, r["mac"] or "")
        conn.execute(
            "UPDATE assets SET device_id = ? WHERE id = ?",
            (did, r["id"]),
        )
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('migration_device_identity_v1', '1')"
    )
    return True


def ensure_device_id_for_upsert(conn: sqlite3.Connection, ip: str, mac: str) -> int:
    row = conn.execute(
        "SELECT id, device_id FROM assets WHERE ip = ?",
        (ip,),
    ).fetchone()
    if row:
        did = row["device_id"]
        if did is not None and int(did) > 0:
            return int(did)
        new_id = _insert_device_row(conn, mac)
        conn.execute(
            "UPDATE assets SET device_id = ? WHERE id = ?",
            (new_id, row["id"]),
        )
        return new_id
    return _insert_device_row(conn, mac)


# ---------------------------------------------------------------------------
# Asset upsert
# ---------------------------------------------------------------------------
def upsert_asset(job_id: int, ip: str, mac: str,
                  ports: list[int], banners: dict[str, str],
                  nmap_cpes: list[str] | None = None,
                  http_titles: dict[int, str] | None = None,
                  http_probe: str | None = None,
                  discovery_sources: list[str] | None = None,
                  connected_via: str = "",
                  hostname: str = "",
                  scan_profile: str = "",
                  scan_mode: str = "auto",
                  ai_cfg: dict[str, object] | None = None,
                  ai_attempts: int = 0,
                  ipv6_addrs: list[str] | None = None) -> dict:
    """Upsert an asset row and return the full row dict.

    Ollama / network I/O for AI enrichment runs only between short DB transactions
    so slow local inference does not hold SQLite locks (which would stall the web UI).
    """
    # full_tcp / fast_full_tcp can time out or filter before -p- completes, yielding
    # zero opens and wiping a good standard_inventory row. Union with prior opens
    # so inventory evidence is never strictly reduced by these profiles alone.
    existing_ports: list[int] = []
    existing_banners: dict[str, str] = {}
    existing_ncpes: list[str] = []
    existing_ipv6: list[str] = []
    with db_conn() as conn:
        cur = conn.execute(
            "SELECT open_ports, banners, nmap_cpes, ipv6_addrs FROM assets WHERE ip=?",
            (ip,),
        ).fetchone()
    if cur:
        try:
            ep = json.loads(cur["open_ports"] or "[]")
            if isinstance(ep, list):
                for x in ep:
                    try:
                        existing_ports.append(int(x))
                    except (TypeError, ValueError):
                        continue
        except (json.JSONDecodeError, TypeError):
            existing_ports = []
        try:
            eb = json.loads(cur["banners"] or "{}")
            if isinstance(eb, dict):
                existing_banners = {str(k): str(v) for k, v in eb.items() if v is not None}
        except (json.JSONDecodeError, TypeError):
            existing_banners = {}
        try:
            en = json.loads(cur["nmap_cpes"] or "[]")
            if isinstance(en, list):
                existing_ncpes = [str(x) for x in en if x]
        except (json.JSONDecodeError, TypeError):
            existing_ncpes = []
        try:
            ev6 = json.loads(cur["ipv6_addrs"] or "[]")
            if isinstance(ev6, list):
                existing_ipv6 = [str(x).strip() for x in ev6 if str(x).strip()]
        except (json.JSONDecodeError, TypeError):
            existing_ipv6 = []

    if scan_profile in ("full_tcp", "fast_full_tcp") and existing_ports:
        new_port_set = set()
        for x in ports or []:
            try:
                new_port_set.add(int(x))
            except (TypeError, ValueError):
                continue
        merged = sorted(new_port_set | set(existing_ports))
        prior_merged = len(merged) > len(new_port_set)
        if prior_merged:
            log.info(
                "[job %d] upsert %s: merging prior open_ports (%d) with scan (%d) → %d for profile=%s",
                job_id,
                ip,
                len(set(existing_ports)),
                len(new_port_set),
                len(merged),
                scan_profile,
            )
        ports = merged
        mb = dict(existing_banners)
        for k, v in (banners or {}).items():
            if v is not None and str(v).strip() != "":
                mb[str(k)] = str(v)
        banners = mb
        if not nmap_cpes and existing_ncpes:
            nmap_cpes = list(existing_ncpes)
        if prior_merged:
            dsc = list(discovery_sources or [])
            if "prior_inventory_ports_merged" not in dsc:
                dsc.append("prior_inventory_ports_merged")
            discovery_sources = dsc

    merged_ipv6 = set(existing_ipv6)
    for v6 in (ipv6_addrs or []):
        s = str(v6 or "").strip().lower()
        if not s:
            continue
        try:
            merged_ipv6.add(str(ipaddress.ip_address(s)))
        except ValueError:
            continue
    merged_ipv6_list = sorted(merged_ipv6)

    fp = fingerprint(
        mac,
        ports,
        banners,
        hostname=hostname,
        routed_scan=(scan_mode == "routed"),
    )
    oui_vendor_pre, oui_cat_pre = oui_lookup(mac)

    # HTTP title enrichment — improve category/vendor from page titles
    if http_titles:
        import re as _re
        for _title in http_titles.values():
            for _pat, _cat, _prod in TITLE_MAP:
                if _re.search(_pat, _title, _re.IGNORECASE):
                    if fp["category"] in ("unk", ""):
                        fp["category"] = _cat
                    if not fp.get("vendor"):
                        fp["vendor"] = _prod
                    break

    # nmap CPE: use it for the CPE field but don't let it override
    # MAC OUI vendor or port-profile category — those signals are more specific
    if nmap_cpes:
        best_nmap_cpe = max(nmap_cpes, key=len)
        # Only set CPE if fingerprint didn't already find one
        if not fp["cpe"]:
            fp["cpe"] = best_nmap_cpe

    # Port profile category takes highest priority (e.g. port 8006 → hv/Proxmox)
    port_cat_effective = ""
    port_cat, port_cpe, _ = classify_from_ports(ports)
    # IPP (631) / JetDirect (9100) hit before DB rules — CUPS on Linux/Photon is not a printer.
    # Must not run after fingerprint() or inventory rescans overwrite VMware Photon → prn.
    skip_printer_port_profile = (
        port_cat == "prn"
        and (
            (hostname and re.search(r"\bphoton\b", hostname, re.I))
            or _printer_banner_conflicts_with_homelab_ports(set(ports))
        )
    )
    if port_cat and port_cat != "unk" and not skip_printer_port_profile:
        port_cat_effective = port_cat
        fp["category"] = port_cat
        if port_cpe:
            vh = vendor_hint_from_port_cpe(port_cpe)
            # Prefer HV/OT or well-known product ports over generic nginx/SSH CPE
            if port_cat in ("hv", "ot") or not fp.get("cpe") or vh:
                fp["cpe"] = cpe_uri_from_port_fragment(port_cpe)
            # If vendor currently equals hardware OUI, promote stronger product identity.
            if vh and (not fp.get("vendor") or fp.get("vendor") == oui_vendor_pre):
                fp["vendor"] = vh

    # Merged HTTP probe (title + headers + body + TLS names) — Kasm body, unknown stacks
    if http_probe:
        hit = _classify_http_probe_blob(http_probe)
        if hit:
            cat_hit, prod = hit
            current_vendor = (fp.get("vendor") or "").strip().lower()
            current_cpe = (fp.get("cpe") or "").lower()
            weak_vendor = current_vendor in {"cisco", "cisco voip", "unknown"}
            weak_cpe = "cisco:ip_phone" in current_cpe or current_cpe.endswith(":sip:*")
            if prod and (not fp.get("vendor") or cat_hit == "voi" or weak_vendor or weak_cpe):
                fp["vendor"] = prod
            if cat_hit == "voi":
                fp["category"] = "voi"
            elif port_cat_effective not in ("hv", "ot") and fp["category"] in (
                "unk", "srv", "ws", "net", "voi", "",
            ):
                fp["category"] = cat_hit
        elif port_cat_effective not in ("hv", "ot"):
            gv = _generic_web_stack_vendor(http_probe)
            if gv and not fp.get("vendor") and fp["category"] in ("unk", "srv", "ws"):
                fp["vendor"] = gv

    ai_enrichment_applied = False
    ai_enrichment_attempted = False
    ai_conf = 0.0
    ai_rationale = ""
    ai_to_cat = str(fp.get("category") or "unk")
    ai_skip_reason = ""
    ai_gate = ""
    if ai_cfg:
        ai_gate = _ai_gate_reason(ai_cfg, fp, ports, banners, hostname, ai_attempts)
        ai_skip_reason = ai_gate
    if ai_cfg and ai_gate == "":
        ai_enrichment_attempted = True
        ai_doc, ai_err = _run_ai_enrichment_ollama(ai_cfg, fp, hostname, ports, banners)
        if ai_doc:
            ai_cat = str(ai_doc.get("category") or "").strip().lower()
            try:
                ai_conf = float(ai_doc.get("confidence") or 0.0)
            except (TypeError, ValueError):
                ai_conf = 0.0
            ai_why = str(ai_doc.get("rationale") or "").strip()
            ai_rationale = ai_why[:500]
            if ai_cat not in {"srv", "ws", "net", "iot", "prn", "hv", "ot", "voi", "unk"}:
                ai_cat = ""
            # Conservative override policy:
            # - only for ambiguous current categories
            # - require moderate confidence
            # - never downgrade strong OT/HV signals
            effective_threshold = float(ai_cfg.get("conf_threshold") or 0.72)
            if fp["category"] in {"net", "srv"} and ai_cat in {"net", "srv"} and ai_cat != fp["category"]:
                effective_threshold = float(ai_cfg.get("conf_threshold_net_srv") or effective_threshold)
            if bool(ai_cfg.get("conflict_only", True)) and ai_cat == fp["category"]:
                ai_skip_reason = "same_category"
            if (
                ai_cat
                and ai_conf >= effective_threshold
                and fp["category"] in {"unk", "net", "srv"}
                and port_cat_effective not in {"hv", "ot"}
                and not (fp["category"] == "net" and ai_cat == "iot")
                and not (bool(ai_cfg.get("conflict_only", True)) and ai_cat == fp["category"])
            ):
                if ai_cat != fp["category"]:
                    prev_cat = fp["category"]
                    ai_to_cat = ai_cat
                    if not bool(ai_cfg.get("suggest_only", False)):
                        fp["category"] = ai_cat
                        ai_enrichment_applied = True
                        if discovery_sources is not None:
                            discovery_sources.append("ai_local_inference")
                        log.info(
                            "[job %d] ai_enrichment_override ip=%s from=%s to=%s conf=%.2f model=%s rationale=%s",
                            job_id, ip, prev_cat, ai_cat, ai_conf, str(ai_cfg.get("model") or ""),
                            (ai_why[:120] if ai_why else ""),
                        )
                    else:
                        ai_skip_reason = "suggest_only"
                else:
                    ai_skip_reason = "same_category"
            elif ai_cat and ai_conf < effective_threshold:
                ai_skip_reason = "low_confidence"
            elif ai_cat and port_cat_effective in {"hv", "ot"}:
                ai_skip_reason = "strong_port_signal"
        elif ai_err and ai_err not in {"timeout", "no_json"}:
            log.info("[job %d] ai_enrichment_skip ip=%s reason=%s", job_id, ip, ai_err[:120])
            ai_skip_reason = ai_err[:120]

    # Vendor precedence:
    #  - vendor: detected service/product identity (Proxmox, Zabbix, etc.)
    #  - mac_vendor: hardware/OUI manufacturer (HP, Dell, etc.)
    # This keeps "Proxmox on HP" from being shown as only "Hewlett Packard".
    vendor     = fp["vendor"]   # may be set from banner
    mac_vendor = fp["vendor"]   # same baseline
    # If OUI gave us a vendor, keep it in mac_vendor; only fill vendor if empty
    oui_vendor, oui_cat = oui_vendor_pre, oui_cat_pre
    if oui_vendor:
        mac_vendor = oui_vendor
        if not vendor:
            vendor = oui_vendor
        # OUI category only fills gap if port profile didn't already classify
        if fp["category"] == "unk" and oui_cat:
            fp["category"] = oui_cat

    routed_override = fp.get("_routed_net_override")
    if isinstance(routed_override, dict):
        log.info(
            "[job %d] routed_net_override ip=%s scan_mode=%s from=%s to=%s has_ssh_22=%s has_web_port=%s linux_banner_hint=%s has_net_oui=%s has_net_hostname_pattern=%s has_net_cpe=%s",
            job_id,
            ip,
            scan_mode,
            routed_override.get("from", "net"),
            routed_override.get("to", "srv"),
            bool(routed_override.get("has_ssh_22")),
            bool(routed_override.get("has_web_port")),
            bool(routed_override.get("linux_banner_hint")),
            bool(routed_override.get("has_net_oui")),
            bool(routed_override.get("has_net_hostname_pattern")),
            bool(routed_override.get("has_net_cpe")),
        )

    with db_conn() as conn:
        device_id = ensure_device_id_for_upsert(conn, ip, mac)

        conn.execute("""
            INSERT INTO assets (ip, hostname, mac, mac_vendor, category, vendor, cpe, os_guess,
                                ai_last_confidence, ai_last_rationale, ai_last_applied, ai_last_suggested_category,
                                ai_last_reason, ai_last_attempted, ai_last_decision_ts,
                                connected_via, open_ports, banners, nmap_cpes, discovery_sources, ipv6_addrs, device_id, last_seen, last_scan_id)
            VALUES (:ip,:host,:mac,:mv,:cat,:vnd,:cpe,:os,
                    :ai_confidence,:ai_rationale,:ai_applied,:ai_suggested_cat,:ai_reason,:ai_attempted,CURRENT_TIMESTAMP,
                    :cv,:ports,:banners,:ncpes,:ds,:v6,:did,CURRENT_TIMESTAMP,:jid)
            ON CONFLICT(ip) DO UPDATE SET
                hostname   = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE hostname END,
                mac        = COALESCE(excluded.mac, mac),
                mac_vendor = COALESCE(excluded.mac_vendor, mac_vendor),
                category   = CASE WHEN excluded.category != 'unk' THEN excluded.category ELSE category END,
                vendor     = COALESCE(NULLIF(excluded.vendor,''), vendor),
                cpe        = CASE
                               WHEN :clear_cpe = 1 THEN ''
                               ELSE COALESCE(NULLIF(excluded.cpe,''), cpe)
                             END,
                os_guess   = COALESCE(NULLIF(excluded.os_guess,''), os_guess),
                ai_last_confidence = CASE
                               WHEN excluded.ai_last_attempted = 1 THEN excluded.ai_last_confidence
                               ELSE ai_last_confidence
                             END,
                ai_last_rationale = CASE
                               WHEN excluded.ai_last_attempted = 1 THEN excluded.ai_last_rationale
                               ELSE ai_last_rationale
                             END,
                ai_last_applied = CASE
                               WHEN excluded.ai_last_attempted = 1 THEN excluded.ai_last_applied
                               ELSE ai_last_applied
                             END,
                ai_last_suggested_category = CASE
                               WHEN excluded.ai_last_attempted = 1 THEN excluded.ai_last_suggested_category
                               ELSE ai_last_suggested_category
                             END,
                ai_last_reason = CASE
                               WHEN excluded.ai_last_reason IS NOT NULL AND excluded.ai_last_reason != '' THEN excluded.ai_last_reason
                               WHEN excluded.ai_last_attempted = 1 THEN excluded.ai_last_reason
                               ELSE ai_last_reason
                             END,
                ai_last_attempted = CASE
                               WHEN excluded.ai_last_attempted = 1 THEN 1
                               ELSE ai_last_attempted
                             END,
                ai_last_decision_ts = CASE
                               WHEN excluded.ai_last_attempted = 1 THEN CURRENT_TIMESTAMP
                               ELSE ai_last_decision_ts
                             END,
                connected_via = COALESCE(NULLIF(excluded.connected_via,''), connected_via),
                open_ports = excluded.open_ports,
                banners    = excluded.banners,
                nmap_cpes  = excluded.nmap_cpes,
                discovery_sources = COALESCE(NULLIF(excluded.discovery_sources,''), discovery_sources),
                ipv6_addrs = CASE
                               WHEN excluded.ipv6_addrs IS NOT NULL AND excluded.ipv6_addrs != '' THEN excluded.ipv6_addrs
                               ELSE ipv6_addrs
                             END,
                last_seen  = CURRENT_TIMESTAMP,
                last_scan_id = excluded.last_scan_id
        """, {
            "ip": ip, "host": hostname, "mac": mac, "mv": mac_vendor,
            "cat": fp["category"], "vnd": vendor,
            "cpe": fp["cpe"], "os": fp["os_guess"],
            "ai_confidence": ai_conf,
            "ai_rationale": ai_rationale,
            "ai_applied": 1 if ai_enrichment_applied else 0,
            "ai_suggested_cat": ai_to_cat if ai_enrichment_attempted else "",
            "ai_reason": ai_skip_reason,
            "ai_attempted": 1 if ai_enrichment_attempted else 0,
            "clear_cpe": 1 if (not fp.get("cpe") and not ports and fp.get("category") in ("unk", "")) else 0,
            "cv": (connected_via or "").strip()[:240],
            "ports":   json.dumps(ports),
            "banners": json.dumps(banners),
            "ncpes":   json.dumps(nmap_cpes or []),
            "ds":      json.dumps(sorted(set(discovery_sources or []))),
            "v6":      json.dumps(merged_ipv6_list),
            "did":     device_id,
            "jid":     job_id,
        })

        nm = _norm_mac(mac)
        if nm:
            conn.execute(
                """UPDATE devices SET updated_at=CURRENT_TIMESTAMP,
                   primary_mac_norm=COALESCE(primary_mac_norm, ?)
                   WHERE id=?""",
                (nm, device_id),
            )

        row = conn.execute("SELECT * FROM assets WHERE ip=?", (ip,)).fetchone()
        result = dict(row)
    result["nmap_cpes"] = json.loads(result.get("nmap_cpes") or "[]")
    result["_routed_net_override_applied"] = isinstance(routed_override, dict)
    result["_ai_enrichment_attempted"] = ai_enrichment_attempted
    result["_ai_enrichment_applied"] = ai_enrichment_applied
    result["_ai_enrichment_confidence"] = ai_conf
    result["_ai_enrichment_suggested_category"] = ai_to_cat
    result["_ai_enrichment_reason"] = ai_skip_reason
    return result


# ---------------------------------------------------------------------------
# Main run_scan
# ---------------------------------------------------------------------------
def run_scan(job: dict) -> None:
    job_id    = job["id"]
    cidrs     = [c.strip() for c in job["target_cidr"].split(",")]
    phases    = json.loads(job["phases"] or "[]")
    scan_mode = job.get("scan_mode", "auto") or "auto"
    rate_pps     = int(job["rate_pps"]    or 5)
    inter_ms     = int(job["inter_delay"] or 200)

    # Enforce profile constraints
    profile_name = (job.get("profile") or DEFAULT_PROFILE)
    profile_obj  = get_profile(profile_name)
    rate_pps     = min(rate_pps, profile_obj.max_rate_pps_cap)
    inter_ms     = max(inter_ms, profile_obj.min_delay_ms)
    phases       = validate_phases(profile_obj, phases)
    ai_cfg = _load_ai_enrichment_settings()

    with db_conn() as conn:
        log_event(conn, job_id, "INFO",
                  f"Profile: {profile_name} — allowed phases: {phases} "
                  f"rate_cap={profile_obj.max_rate_pps_cap}pps "
                  f"min_delay={profile_obj.min_delay_ms}ms")
        if bool(ai_cfg.get("available")):
            log_event(
                conn, job_id, "INFO",
                f"AI enrichment enabled: provider={ai_cfg.get('provider')} model={ai_cfg.get('model')} "
                f"timeout_ms={ai_cfg.get('timeout_ms')} max_hosts={ai_cfg.get('max_hosts_per_scan')} "
                f"ambiguous_only={ai_cfg.get('ambiguous_only')} suggest_only={ai_cfg.get('suggest_only')} "
                f"conflict_only={ai_cfg.get('conflict_only')} conf={ai_cfg.get('conf_threshold')} "
                f"conf_net_srv={ai_cfg.get('conf_threshold_net_srv')}"
            )
        elif bool(ai_cfg.get("enabled")):
            log_event(
                conn, job_id, "INFO",
                f"AI enrichment unavailable: reason={ai_cfg.get('availability_reason') or 'runtime_unreachable'} "
                f"provider={ai_cfg.get('provider')} model={ai_cfg.get('model')}"
            )
    excl_raw  = job["exclusions"] or ""

    # Parse exclusion list (IPs, CIDR ranges, comments)
    excludes: set[str] = set()
    target_nets: list[ipaddress._BaseNetwork] = []
    for c in cidrs:
        try:
            target_nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    for line in excl_raw.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        if "/" in line:
            try:
                for ip in ipaddress.ip_network(line, strict=False).hosts():
                    excludes.add(str(ip))
            except ValueError:
                pass
        elif "-" in line and line.count(".") == 3:
            # Range like 192.168.1.10-20
            try:
                base, end = line.rsplit("-", 1)
                base_parts = base.split(".")
                start_int  = int(base_parts[-1])
                end_int    = int(end)
                prefix     = ".".join(base_parts[:-1])
                for n in range(start_int, end_int + 1):
                    excludes.add(f"{prefix}.{n}")
            except (ValueError, IndexError):
                pass
        else:
            excludes.add(line)

    with db_conn() as conn:
        conn.execute("UPDATE scan_jobs SET status='running', started_at=CURRENT_TIMESTAMP WHERE id=?", (job_id,))
        log_event(conn, job_id, "INFO", f"Scan started — target: {job['target_cidr']} phases: {phases}")
        log_event(conn, job_id, "INFO", f"Exclusion list loaded: {len(excludes)} entries")

    # ---- Phase 1: Passive ------------------------------------------------
    passive_hosts: set[str] = set()
    passive_signal_map: dict[str, set[str]] = {}
    passive_ndp_ipv6_by_mac: dict[str, set[str]] = {}
    if "passive" in phases:
        with db_conn() as conn:
            log_event(conn, job_id, "INFO", "Phase 1: passive ARP/mDNS sniff starting")
        try:
            passive_hosts, passive_signal_map, passive_ndp_ipv6_by_mac = phase_passive(job_id, cidrs[0], timeout_secs=20)
        except PermissionError as e:
            log.warning("[job %d] Passive phase skipped (no raw socket permission): %s", job_id, e)
            passive_hosts = set()
            passive_signal_map = {}
            passive_ndp_ipv6_by_mac = {}

    # ---- Phase 2: Host discovery -----------------------------------------
    alive_hosts: dict[str, str] = {}  # ip -> mac
    if "icmp" in phases:
        with db_conn() as conn:
            log_event(conn, job_id, "INFO",
                      f"Phase 2: host discovery (mode={scan_mode})")
        alive_hosts = phase_discovery(job_id, cidrs, excludes, rate_pps,
                                      scan_mode=scan_mode)

    # Merge passive + active discovery
    all_ips = (set(alive_hosts.keys()) | passive_hosts) - excludes

    # Routed full-TCP scans can miss hosts at discovery time (-sn ping scan),
    # especially over VPN/tunnel paths where ICMP/TCP ping probes are filtered.
    # For explicit full_tcp/fast_full_tcp in routed mode, seed candidates from
    # the target CIDR so phase 3 can still attempt real port probing.
    if profile_obj.name in ("full_tcp", "fast_full_tcp") and scan_mode == "routed":
        max_seed_hosts = 1024
        seeded: set[str] = set()
        for net in target_nets:
            # Skip very large ranges to avoid explosive full-port scans.
            host_count = max(0, net.num_addresses - 2)
            if host_count > max_seed_hosts:
                with db_conn() as conn:
                    log_event(
                        conn, job_id, "WARN",
                        f"Routed full-TCP seed skipped for {net} ({host_count} hosts > {max_seed_hosts} cap)"
                    )
                continue
            for ip in net.hosts():
                ip_s = str(ip)
                if ip_s in excludes:
                    continue
                seeded.add(ip_s)
        add_n = len(seeded - all_ips)
        if add_n > 0:
            all_ips |= seeded
            with db_conn() as conn:
                log_event(
                    conn, job_id, "INFO",
                    f"Routed full-TCP candidate expansion: +{add_n} hosts from target CIDR"
                )

    with db_conn() as conn:
        conn.execute("UPDATE scan_jobs SET hosts_found=? WHERE id=?", (len(all_ips), job_id))
        log_event(conn, job_id, "INFO", f"Discovery complete: {len(all_ips)} unique hosts")

    # Abort check after discovery
    if is_aborted(job_id):
        log.info("[job %d] Aborted by user after discovery phase", job_id)
        return

    # ---- Phase 3: Banner / fingerprint -----------------------------------
    banner_results: dict[str, dict] = {}
    if "banner" in phases or "fingerprint" in phases:
        with db_conn() as conn:
            log_event(conn, job_id, "INFO", "Phase 3: banner grab / fingerprinting")
        # Scan ordering matters for operator feedback on larger/routed ranges:
        # prioritize discovery-confirmed alive hosts first, then the rest.
        alive_first = [ip for ip in alive_hosts.keys() if ip in all_ips]
        rest = [ip for ip in all_ips if ip not in alive_hosts]
        try:
            alive_first.sort(key=lambda s: ipaddress.ip_address(s))
            rest.sort(key=lambda s: ipaddress.ip_address(s))
        except ValueError:
            alive_first.sort()
            rest.sort()
        ordered_hosts = alive_first + rest
        if ordered_hosts:
            with db_conn() as conn:
                log_event(
                    conn, job_id, "INFO",
                    f"Phase 3 ordering: {len(alive_first)} discovery-confirmed hosts first, {len(rest)} fallback hosts"
                )
        # Two-pass strategy:
        # 1) Scan discovery-confirmed hosts first (small set => richer timeout tier).
        # 2) Scan fallback CIDR-expanded hosts after, optimized for throughput.
        banner_results = {}
        if alive_first:
            with db_conn() as conn:
                log_event(conn, job_id, "INFO",
                          f"Phase 3 pass 1: scanning {len(alive_first)} confirmed-alive hosts")
            banner_results.update(
                phase_banner(job_id, alive_first, rate_pps, inter_ms, job=job)
            )
        if rest:
            with db_conn() as conn:
                log_event(conn, job_id, "INFO",
                          f"Phase 3 pass 2: scanning {len(rest)} fallback hosts")
            banner_results.update(
                phase_banner(job_id, rest, rate_pps, inter_ms, job=job)
            )

    # ---- Phase 3b: Enrichment -------------------------------------------
    # Must run BEFORE the upsert loop so enrichment data is available per-host
    enrichment_map: dict[str, dict] = {}
    if HAS_ENRICHMENT:
        try:
            enrich_ids = _parse_job_enrichment_ids(job)
            if enrich_ids is not None and len(enrich_ids) == 0:
                with db_conn() as conn:
                    log_event(
                        conn, job_id, "INFO",
                        "Phase 3b skipped: no enrichment sources selected for this scan",
                    )
                enrichment_map = {}
            else:
                with db_conn() as conn:
                    log_event(conn, job_id, "INFO", "Phase 3b: network enrichment (configured sources)")
                # phase_enrich does external I/O — must not share db_conn with log_event above
                enrichment_map = phase_enrich(job_id, enrich_ids) or {}
            if enrichment_map:
                log.info("[job %d] Applying enrichment to %d assets", job_id, len(enrichment_map))
        except Exception as e:
            log.warning("[job %d] Enrichment phase error (non-fatal): %s", job_id, e)
            enrichment_map = {}

    # Enrichment can discover routed hosts that phase_discovery misses.
    # Include in-scope enrichment IP keys in the host set before upsert.
    if enrichment_map:
        enrich_ips: set[str] = set()
        for k in enrichment_map.keys():
            if not isinstance(k, str) or not k or k.startswith("mac:"):
                continue
            try:
                ip_obj = ipaddress.ip_address(k)
            except ValueError:
                continue
            if target_nets and not any(ip_obj in net for net in target_nets):
                continue
            if k in excludes:
                continue
            enrich_ips.add(k)
        added = len(enrich_ips - all_ips)
        if added > 0:
            all_ips |= enrich_ips
            with db_conn() as conn:
                conn.execute("UPDATE scan_jobs SET hosts_found=? WHERE id=?", (len(all_ips), job_id))
                log_event(conn, job_id, "INFO",
                          f"Enrichment expanded host set: +{added} in-scope hosts ({len(all_ips)} total)")

    # ---- Upsert assets ---------------------------------------------------
    upserted_assets: list[dict] = []
    scanned = 0
    routed_override_count = 0
    ai_enrichment_attempts = 0
    ai_enrichment_applied = 0
    ai_reason_counts: dict[str, int] = {}
    # Resolve hostnames for all discovered hosts (not just those with open ports)
    # This is important for ARP-only hosts like phones/tablets with randomized MACs
    log.info("[job %d] Resolving hostnames for %d hosts...", job_id, len(all_ips))
    hostname_cache: dict[str, str] = {}
    with db_conn() as conn:
        # Pre-populate from existing DB entries to avoid redundant lookups
        if all_ips:
            placeholders = ",".join("?" * len(all_ips))
            rows = conn.execute(
                f"SELECT ip, hostname FROM assets WHERE ip IN ({placeholders}) AND hostname != ''",
                list(all_ips)
            ).fetchall()
            for row in rows:
                hostname_cache[row["ip"]] = row["hostname"]

    # ---- Phase 3c: HTTP title grabbing -----------------------------------
    http_titles: dict[str, dict[int, str]] = {}
    http_probes: dict[str, str] = {}
    if "banner" in phases and profile_obj.allow_banner:
        http_titles, http_probes = phase_http_titles(job_id, banner_results)

    resolved_dns_hosts: set[str] = set()
    for idx, ip in enumerate(sorted(all_ips), start=1):
        if ip not in hostname_cache:
            hn = resolve_hostname(ip)
            hostname_cache[ip] = hn
            if hn:
                resolved_dns_hosts.add(ip)
        if idx % 32 == 0 or idx == len(all_ips):
            with db_conn() as conn:
                log_event(conn, job_id, "INFO",
                          f"Hostname resolution progress: {idx}/{len(all_ips)} hosts")

    for ip in all_ips:
        mac     = alive_hosts.get(ip, "")
        br      = banner_results.get(ip, {})
        ports   = br.get("ports", [])
        banners = br.get("banners", {})

        # Merge HTTP titles into banners for display
        titles = http_titles.get(ip, {})
        for port, title in titles.items():
            if port not in banners or not banners[port]:
                banners[port] = f"[{title}]"  # bracket = title not banner
        if http_probes.get(ip):
            banners["_http"] = http_probes[ip][:8000]

        nmap_cpes = br.get("nmap_cpes", [])
        hostname  = br.get("hostname", "") or hostname_cache.get(ip, "")
        connected_via = ""
        sources: list[str] = []
        if ip in passive_hosts:
            sources.append("passive_mdns_or_arp")
            for sig in sorted(passive_signal_map.get(ip, set())):
                sources.append(f"passive_{sig}")
        if ip in alive_hosts:
            sm = (job.get("scan_mode") or "auto")
            sources.append(f"discovery_{sm}")
            if alive_hosts.get(ip):
                sources.append("mac_from_discovery")
        if ports:
            sources.append("open_ports_detected")
        if br.get("hostname"):
            sources.append("hostname_from_nmap_or_banner")
        if ip in resolved_dns_hosts:
            sources.append("hostname_from_dns_mdns_netbios")
        if http_titles.get(ip):
            sources.append("http_title_probe")
        if http_probes.get(ip):
            sources.append("http_probe_blob")

        # Apply enrichment data — fills in MAC, hostname, vendor for cross-subnet hosts
        enrich = enrichment_map.get(ip, {})
        if (not enrich) and mac:
            enrich = enrichment_map.get(f"mac:{str(mac).strip().lower()}", {})
        if enrich:
            sources.append("enrichment_source")
            enrich_src = str(enrich.get("source", "") or "").lower()
            from_dhcp = "dhcp" in enrich_src
            from_dns_log = "dns_log" in enrich_src or "dnslogs" in enrich_src
            from_lldp_cdp = "snmp_lldp:" in enrich_src or "snmp_cdp:" in enrich_src
            from_switch_fdb = "snmp_fdb:" in enrich_src
            from_firewall_log = "firewall_log" in enrich_src
            raw = enrich.get("raw") if isinstance(enrich.get("raw"), dict) else {}
            if not connected_via:
                if from_switch_fdb:
                    ifdescr = str(raw.get("ifdescr", "") or "").strip()
                    bport = str(raw.get("bridge_port", "") or "").strip()
                    src_target = enrich_src.split("snmp_fdb:", 1)[1] if "snmp_fdb:" in enrich_src else ""
                    if ifdescr:
                        connected_via = f"SNMP FDB via {src_target} port {ifdescr}"
                    elif bport:
                        connected_via = f"SNMP FDB via {src_target} bridge-port {bport}"
                elif from_lldp_cdp and enrich.get("description"):
                    connected_via = str(enrich.get("description") or "").strip()
                elif "unifi" in enrich_src:
                    unifi_cv = str(enrich.get("connected_via", "") or "").strip()
                    if unifi_cv:
                        connected_via = unifi_cv
                    else:
                        sw_port = str(enrich.get("sw_port", "") or "").strip()
                        sw_mac = str(enrich.get("sw_mac", "") or "").strip()
                        if sw_port and sw_mac:
                            connected_via = f"UniFi switch {sw_mac} port {sw_port}"
                    ap_mac = str(enrich.get("ap_mac", "") or "").strip()
                    if (not connected_via) and ap_mac:
                        connected_via = f"UniFi AP {ap_mac}"
            if from_firewall_log:
                sources.append("seen_in_firewall_log")
            # Enrichment MAC wins if we didn't get one from ARP (cross-subnet case)
            if not mac and enrich.get("mac"):
                mac = enrich["mac"]
                if from_dhcp:
                    sources.append("mac_from_dhcp_lease")
                elif from_switch_fdb:
                    sources.append("mac_from_switch_fdb")
                elif from_firewall_log:
                    sources.append("mac_from_firewall_log")
                else:
                    sources.append("mac_from_enrichment")
            # Enrichment hostname wins if scanner got nothing
            if not hostname and enrich.get("hostname"):
                hostname = enrich["hostname"]
                if from_dhcp:
                    sources.append("hostname_from_dhcp_lease")
                elif from_dns_log:
                    sources.append("hostname_from_dns_log")
                elif from_lldp_cdp:
                    sources.append("hostname_from_lldp_cdp")
                elif from_firewall_log:
                    sources.append("hostname_from_firewall_log")
                else:
                    sources.append("hostname_from_enrichment")

        ipv6_addrs: list[str] = []
        macn = _norm_mac(mac)
        if macn and macn in passive_ndp_ipv6_by_mac:
            ipv6_addrs = sorted(passive_ndp_ipv6_by_mac.get(macn, set()))
            if ipv6_addrs:
                sources.append("ipv6_from_ndp")

        # Only record assets we have actual evidence for:
        # - Has a MAC address (ARP/discovery/enrichment)
        # - Has at least one open port
        # - Was seen passively (mDNS/ARP sniff)
        # - Has enrichment evidence for this IP/MAC
        # For routed scans, enrichment may be the only positive signal.
        if not mac and not ports and ip not in passive_hosts and not enrich:
            continue

        asset = upsert_asset(
            job_id, ip, mac, ports, banners, nmap_cpes,
            http_titles=http_titles.get(ip, {}),
            http_probe=http_probes.get(ip),
            discovery_sources=sources,
            connected_via=connected_via,
            hostname=hostname,
            scan_profile=profile_name,
            scan_mode=scan_mode,
            ai_cfg=ai_cfg,
            ai_attempts=ai_enrichment_attempts,
            ipv6_addrs=ipv6_addrs,
        )
        upserted_assets.append(asset)
        if asset.get("_routed_net_override_applied"):
            routed_override_count += 1
        if asset.get("_ai_enrichment_attempted"):
            ai_enrichment_attempts += 1
        if asset.get("_ai_enrichment_applied"):
            ai_enrichment_applied += 1
        ai_reason = str(asset.get("_ai_enrichment_reason") or "").strip()
        if ai_reason:
            ai_reason_counts[ai_reason] = ai_reason_counts.get(ai_reason, 0) + 1
        scanned += 1
        with db_conn() as conn:
            conn.execute("UPDATE scan_jobs SET hosts_scanned=? WHERE id=?", (scanned, job_id))

        # Periodic abort check — every 10 hosts
        if scanned % 10 == 0 and is_aborted(job_id):
            log.info("[job %d] Aborted by user during asset cataloguing", job_id)
            return

    # ---- Phase 4: CVE correlation ----------------------------------------
    if "cve" in phases:
        with db_conn() as conn:
            log_event(conn, job_id, "INFO", "Phase 4: CVE correlation (SQLite indexed lookup)")

        findings = phase_cve(job_id, upserted_assets)

        with db_conn() as conn:
            for i, f in enumerate(findings):
                conn.execute("""
                    INSERT INTO findings (asset_id, ip, cve_id, cvss, severity, description, published)
                    VALUES (:aid,:ip,:cve,:cvss,:sev,:desc,:pub)
                    ON CONFLICT(asset_id, cve_id) DO UPDATE SET
                        cvss=excluded.cvss, severity=excluded.severity,
                        description=excluded.description
                """, {
                    "aid":  f["asset_id"], "ip": f["ip"],
                    "cve":  f["cve_id"],   "cvss": f["cvss"],
                    "sev":  f["severity"], "desc": f["description"],
                    "pub":  f["published"],
                })
                if (i + 1) % _BULK_WRITE_COMMIT_INTERVAL == 0:
                    conn.commit()

            # Update top_cve / top_cvss on each asset
            conn.execute("""
                UPDATE assets SET
                    top_cve  = (SELECT cve_id FROM findings WHERE asset_id=assets.id AND resolved=0 ORDER BY cvss DESC LIMIT 1),
                    top_cvss = (SELECT cvss   FROM findings WHERE asset_id=assets.id AND resolved=0 ORDER BY cvss DESC LIMIT 1)
                WHERE id IN (SELECT DISTINCT asset_id FROM findings)
            """)

    # ---- Done ------------------------------------------------------------
    summary = {
        "profile": profile_name,
        "scan_mode": scan_mode,
        "target_cidr": job.get("target_cidr", ""),
        "phases": phases,
        "assets_catalogued": int(scanned),
        "hosts_found": int(len(all_ips)),
        "open_findings": 0,
        "routed_net_overrides": int(routed_override_count),
        "ai_enrichment_attempts": int(ai_enrichment_attempts),
        "ai_enrichment_applied": int(ai_enrichment_applied),
        "ai_reason_counts": dict(sorted(ai_reason_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "open_ports_total": 0,
        "top_ports": [],
        "categories": {},
    }
    try:
        with db_conn() as conn:
            finding_count = conn.execute(
                """
                SELECT COUNT(*)
                FROM findings f
                JOIN assets a ON a.id = f.asset_id
                WHERE a.last_scan_id = ? AND f.resolved = 0
                """,
                (job_id,),
            ).fetchone()[0]
            summary["open_findings"] = int(finding_count or 0)
            sev_rows = conn.execute(
                """
                SELECT severity, COUNT(*) AS c
                FROM findings f
                JOIN assets a ON a.id = f.asset_id
                WHERE a.last_scan_id = ? AND f.resolved = 0
                GROUP BY severity
                """,
                (job_id,),
            ).fetchall()
            sev_counts: dict[str, int] = {}
            for sr in sev_rows:
                s = str(sr["severity"] or "").strip().lower() or "unknown"
                sev_counts[s] = int(sr["c"] or 0)
            summary["severity_breakdown"] = sev_counts

            rows = conn.execute(
                "SELECT open_ports, category FROM assets WHERE last_scan_id = ?",
                (job_id,),
            ).fetchall()
            port_counts: dict[int, int] = {}
            cat_counts: dict[str, int] = {}
            open_total = 0
            for row in rows:
                cat = str(row["category"] or "unk").strip() or "unk"
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
                try:
                    ports = json.loads(row["open_ports"] or "[]")
                except Exception:
                    ports = []
                if not isinstance(ports, list):
                    ports = []
                for p in ports:
                    try:
                        pi = int(p)
                    except (TypeError, ValueError):
                        continue
                    if pi <= 0 or pi > 65535:
                        continue
                    open_total += 1
                    port_counts[pi] = port_counts.get(pi, 0) + 1
            summary["open_ports_total"] = int(open_total)
            summary["top_ports"] = [
                {"port": p, "hosts": c}
                for p, c in sorted(port_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
            ]
            summary["categories"] = dict(sorted(cat_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:8])
    except Exception as e:
        log.warning("[job %d] Could not build history summary: %s", job_id, e)

    # Optional AI executive summary for this run (always record outcome when AI is enabled).
    summary["ai_scan_summary_status"] = "skipped_disabled"
    summary["ai_scan_summary_detail"] = ""
    if bool(ai_cfg.get("enabled")):
        ac = int(summary.get("assets_catalogued", 0))
        if ac <= 0:
            summary["ai_scan_summary_status"] = "skipped_no_assets"
            summary["ai_scan_summary_detail"] = "No catalogued assets for this run"
        elif not bool(ai_cfg.get("available")):
            summary["ai_scan_summary_status"] = "skipped_runtime"
            summary["ai_scan_summary_detail"] = str(ai_cfg.get("availability_reason") or "runtime_unreachable")
        else:
            ai_scan_doc, ai_scan_err = _run_ai_scan_summary_ollama(ai_cfg, summary)
            if ai_scan_doc:
                summary["ai_summary"] = ai_scan_doc
                summary["ai_scan_summary_status"] = "ok"
            else:
                err = (ai_scan_err or "unknown")[:200]
                summary["ai_scan_summary_status"] = "failed"
                summary["ai_scan_summary_detail"] = err
                log.info("[job %d] ai_scan_summary_skip reason=%s", job_id, err[:120])

    with db_conn() as conn:
        # Preserve run-specific evidence so historical scan details remain stable
        # even after later scans update assets.last_scan_id.
        snap_rows = conn.execute(
            """
            SELECT id, ip, hostname, category, vendor, top_cve, top_cvss, open_ports, device_id
            FROM assets
            WHERE last_scan_id = ?
            ORDER BY ip ASC
            """,
            (job_id,),
        ).fetchall()
        conn.execute("DELETE FROM scan_asset_snapshots WHERE job_id = ?", (job_id,))
        if snap_rows:
            snap_data = [
                (
                    job_id,
                    int(r["id"]) if r["id"] is not None else None,
                    r["ip"],
                    r["hostname"],
                    r["category"],
                    r["vendor"],
                    r["top_cve"],
                    r["top_cvss"],
                    r["open_ports"],
                    int(r["device_id"]) if r["device_id"] is not None else None,
                )
                for r in snap_rows
            ]
            ins_snap = """
                INSERT INTO scan_asset_snapshots
                    (job_id, asset_id, ip, hostname, category, vendor, top_cve, top_cvss, open_ports, device_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            for j in range(0, len(snap_data), _BULK_WRITE_COMMIT_INTERVAL):
                conn.executemany(ins_snap, snap_data[j : j + _BULK_WRITE_COMMIT_INTERVAL])
                conn.commit()
        conn.execute("DELETE FROM scan_finding_snapshots WHERE job_id = ?", (job_id,))
        finding_rows = conn.execute(
            """
            SELECT f.asset_id, f.cve_id, f.cvss, f.severity, COALESCE(f.resolved, 0) AS resolved
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            WHERE a.last_scan_id = ?
            """,
            (job_id,),
        ).fetchall()
        if finding_rows:
            fr_data = [
                (
                    job_id,
                    int(fr["asset_id"]),
                    fr["cve_id"],
                    fr["cvss"],
                    fr["severity"],
                    int(fr["resolved"] or 0),
                )
                for fr in finding_rows
            ]
            ins_fs = """
                INSERT INTO scan_finding_snapshots
                    (job_id, asset_id, cve_id, cvss, severity, resolved)
                VALUES (?, ?, ?, ?, ?, ?)
            """
            for j in range(0, len(fr_data), _BULK_WRITE_COMMIT_INTERVAL):
                conn.executemany(ins_fs, fr_data[j : j + _BULK_WRITE_COMMIT_INTERVAL])
                conn.commit()

        conn.execute("""
            UPDATE scan_jobs
            SET status='done', finished_at=CURRENT_TIMESTAMP, hosts_scanned=?, summary_json=?
            WHERE id=?
        """, (scanned, json.dumps(summary), job_id))
        log_event(conn, job_id, "INFO",
                  f"Scan complete — {scanned} assets catalogued, {len(upserted_assets)} upserted, "
                  f"routed_net_overrides={routed_override_count}, "
                  f"ai_enrichment_attempts={ai_enrichment_attempts}, ai_enrichment_applied={ai_enrichment_applied}")


# ---------------------------------------------------------------------------
# Daemon loop — job queue with priority, retry, and failure tracking
# ---------------------------------------------------------------------------

MAX_RETRIES   = 2    # default max retries for transient failures
RETRY_DELAY_S = 30   # seconds to wait before retrying a failed job

# Failures that are worth retrying (transient)
RETRYABLE_ERRORS = (
    "timeout", "connection", "nmap", "network", "unreachable",
    "database is locked", "busy",
)

def _is_retryable(error: str) -> bool:
    """Return True if the error message suggests a transient failure."""
    err_lower = (error or "").lower()
    return any(keyword in err_lower for keyword in RETRYABLE_ERRORS)


def _mark_failed(conn: sqlite3.Connection, job_id: int,
                 error: str, failure_reason: str = "") -> None:
    """Mark a job as failed with structured reason."""
    conn.execute("""
        UPDATE scan_jobs
        SET status='failed', error_msg=?, failure_reason=?,
            finished_at=CURRENT_TIMESTAMP
        WHERE id=?
    """, (str(error)[:500], failure_reason or str(error)[:200], job_id))


def _schedule_retry(conn: sqlite3.Connection, job: dict, error: str) -> None:
    """
    Increment retry_count and re-queue the job if under max_retries.
    Otherwise mark it as permanently failed.
    """
    retry_count = int(job.get("retry_count") or 0) + 1
    max_retries = int(job.get("max_retries") or MAX_RETRIES)

    if retry_count <= max_retries:
        log.info("Job #%d scheduling retry %d/%d in %ds",
                 job["id"], retry_count, max_retries, RETRY_DELAY_S)
        conn.execute("""
            UPDATE scan_jobs
            SET status='queued', retry_count=?, error_msg=?,
                started_at=NULL,
                created_at=datetime('now', '+%d seconds')
            WHERE id=?
        """ % (RETRY_DELAY_S, "?"),   # SQLite datetime offset
            (retry_count, f"Retry {retry_count}/{max_retries}: {error}"[:200],
             job["id"])
        )
        # Fix: use proper approach for delayed retry
        conn.execute("""
            UPDATE scan_jobs
            SET status='retrying', retry_count=?, error_msg=?,
                started_at=NULL, finished_at=NULL
            WHERE id=?
        """, (retry_count, f"Retry {retry_count}/{max_retries}: {str(error)[:150]}", job["id"]))
        log.info("Job #%d marked as retrying (%d/%d)", job["id"], retry_count, max_retries)
    else:
        log.warning("Job #%d exceeded max retries (%d), marking failed", job["id"], max_retries)
        conn.execute("""
            UPDATE scan_jobs
            SET status='failed', retry_count=?, error_msg=?,
                failure_reason=?, finished_at=CURRENT_TIMESTAMP
            WHERE id=?
        """, (retry_count,
              f"Failed after {max_retries} retries: {str(error)[:150]}",
              "max_retries_exceeded",
              job["id"]))


# ---------------------------------------------------------------------------
# OUI backfill — enrich existing assets that have MAC but no vendor
# ---------------------------------------------------------------------------
def backfill_oui(conn: sqlite3.Connection) -> int:
    """
    For all assets with a MAC address but no vendor set, run OUI lookup
    and update vendor/category. Safe to run repeatedly — skips if vendor exists.
    Returns count of updated assets.
    """
    rows = conn.execute(
        "SELECT id, mac, category FROM assets WHERE mac != '' AND (vendor IS NULL OR vendor = '')"
    ).fetchall()

    updated = 0
    for row in rows:
        oui_vendor, oui_cat = oui_lookup(row["mac"])
        if not oui_vendor:
            continue
        conn.execute("""
            UPDATE assets SET
                vendor   = ?,
                mac_vendor = ?,
                category = CASE WHEN category = 'unk' THEN ? ELSE category END
            WHERE id = ?
        """, (oui_vendor, oui_vendor,
                oui_cat if oui_cat else 'unk',
                row["id"]))
        updated += 1

    if updated:
        log.info("OUI backfill: updated %d assets", updated)
    return updated


def backfill_proxmox_hostnames(conn: sqlite3.Connection) -> int:
    """
    Backfill hostname from stored Proxmox web banners for legacy rows where
    hostname is still blank.
    """
    rows = conn.execute(
        "SELECT id, ip, hostname, banners FROM assets WHERE (hostname IS NULL OR hostname='')"
    ).fetchall()
    updated = 0
    for row in rows:
        try:
            banners = json.loads(row["banners"] or "{}")
        except Exception:
            banners = {}
        found = ""
        for b in (banners.values() if isinstance(banners, dict) else []):
            if not isinstance(b, str):
                continue
            m = re.search(r"\[?\s*([A-Za-z0-9._-]+)\s*-\s*Proxmox Virtual Environment\]?", b, re.I)
            if m:
                found = m.group(1).strip()
                break
        if found:
            conn.execute("UPDATE assets SET hostname=? WHERE id=?", (found, row["id"]))
            updated += 1
    if updated:
        log.info("Proxmox hostname backfill: updated %d assets", updated)
    return updated


def recover_stale_running_jobs(conn: sqlite3.Connection) -> int:
    """
    On daemon startup, mark any leftover 'running' jobs as aborted.
    These can happen if the daemon/service restarts mid-scan.
    """
    rows = conn.execute(
        "SELECT id FROM scan_jobs WHERE status='running'"
    ).fetchall()
    if not rows:
        return 0

    recovered = 0
    recovered_ids: list[int] = []
    for row in rows:
        jid = int(row["id"])
        conn.execute("""
            UPDATE scan_jobs
            SET status='aborted',
                finished_at=CURRENT_TIMESTAMP,
                error_msg=COALESCE(error_msg,'') ||
                          CASE WHEN COALESCE(error_msg,'')='' THEN '' ELSE ' | ' END ||
                          'Daemon restarted while scan was running'
            WHERE id=? AND status='running'
        """, (jid,))
        try:
            log_event(conn, jid, "WARN", "Job auto-aborted after daemon restart")
        except Exception:
            pass
        recovered += 1
        recovered_ids.append(jid)

    if recovered:
        log.warning(
            "Recovered %d stale running job(s) from previous daemon session: %s",
            recovered, ",".join(str(x) for x in recovered_ids)
        )
    return recovered


def _feed_scan_batches(conn: sqlite3.Connection, queue_cap: int = 10) -> int:
    """
    Promote queued work from scan_batches.pending_targets into scan_jobs as slots free up.
    Returns number of jobs enqueued in this pass.
    """
    in_flight = int(conn.execute(
        "SELECT COUNT(*) FROM scan_jobs WHERE status IN ('running','queued','retrying')"
    ).fetchone()[0])
    slots = max(0, int(queue_cap) - in_flight)
    if slots <= 0:
        return 0

    enqueued = 0
    while slots > 0:
        b = conn.execute(
            """
            SELECT id, label, created_by, pending_targets, total_targets, exclusions, phases,
                   rate_pps, inter_delay, scan_mode, profile, priority, enrichment_source_ids
            FROM scan_batches
            WHERE status IN ('active', 'queued_all')
            ORDER BY id ASC
            LIMIT 1
            """
        ).fetchone()
        if not b:
            break
        try:
            pending = json.loads(b["pending_targets"] or "[]")
        except Exception:
            pending = []
        if not isinstance(pending, list):
            pending = []
        pending = [str(x).strip() for x in pending if str(x).strip()]
        if not pending:
            conn.execute(
                "UPDATE scan_batches SET status='queued_all', updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (int(b["id"]),),
            )
            continue

        target = pending.pop(0)
        total_targets = int(b["total_targets"] or 0)
        if total_targets <= 0:
            total_targets = len(pending) + 1
        batch_index = total_targets - len(pending)
        label_base = (str(b["label"] or "") or "Scan batch").strip()
        label = f"{label_base} [batch {batch_index}/{total_targets}]"
        conn.execute(
            """
            INSERT INTO scan_jobs (target_cidr, label, exclusions, phases, rate_pps, inter_delay,
                                   scan_mode, profile, priority, created_by, enrichment_source_ids,
                                   batch_id, batch_index, batch_total)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target,
                label,
                b["exclusions"] or "",
                b["phases"] or "[]",
                int(b["rate_pps"] or 5),
                int(b["inter_delay"] or 200),
                str(b["scan_mode"] or "auto"),
                str(b["profile"] or "standard_inventory"),
                int(b["priority"] or 10),
                str(b["created_by"] or "web"),
                b["enrichment_source_ids"],
                int(b["id"]),
                batch_index,
                total_targets,
            ),
        )
        conn.execute(
            "UPDATE scan_batches SET pending_targets=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (json.dumps(pending), ("queued_all" if not pending else "active"), int(b["id"])),
        )
        enqueued += 1
        slots -= 1
    return enqueued


def _refresh_scan_batch_statuses(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT id, status, total_targets, pending_targets
        FROM scan_batches
        WHERE status IN ('active', 'queued_all')
        """
    ).fetchall()
    for b in rows:
        bid = int(b["id"])
        stats = conn.execute(
            """
            SELECT
                SUM(CASE WHEN status='done' THEN 1 ELSE 0 END) AS done_count,
                SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failed_count,
                SUM(CASE WHEN status='aborted' THEN 1 ELSE 0 END) AS aborted_count,
                SUM(CASE WHEN status IN ('queued','running','retrying') THEN 1 ELSE 0 END) AS inflight_count
            FROM scan_jobs
            WHERE batch_id = ?
            """,
            (bid,),
        ).fetchone()
        done_count = int((stats["done_count"] or 0) if stats else 0)
        failed_count = int((stats["failed_count"] or 0) if stats else 0)
        aborted_count = int((stats["aborted_count"] or 0) if stats else 0)
        inflight_count = int((stats["inflight_count"] or 0) if stats else 0)
        try:
            pending = json.loads(b["pending_targets"] or "[]")
        except Exception:
            pending = []
        pending_count = len(pending) if isinstance(pending, list) else 0
        if pending_count == 0 and inflight_count == 0:
            new_status = "completed" if (failed_count + aborted_count) == 0 else "failed_partial"
            if str(b["status"] or "") != new_status:
                conn.execute(
                    "UPDATE scan_batches SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (new_status, bid),
                )


# ---------------------------------------------------------------------------
# Daemon main loop — job queue with priority, retry, and failure tracking
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("SurveyTrace scanner daemon starting (db: %s)", DB_PATH)
    log.info("Daemon startup marker: pid=%d ts=%s", os.getpid(), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Load synced fingerprint feeds if present
    oui_loaded = load_external_oui_map(OUI_MAP_PATH)
    if oui_loaded:
        log.info("Loaded external OUI map: %d prefixes (%s)", oui_loaded, OUI_MAP_PATH)
    else:
        log.info("No external OUI map loaded (run sync_oui.py)")

    webfp_loaded = load_external_webfp_rules(WEBFP_RULES_PATH)
    if webfp_loaded:
        log.info("Loaded external web fingerprint rules: %d (%s)", webfp_loaded, WEBFP_RULES_PATH)
    else:
        log.info("No external web fingerprint rules loaded (run sync_webfp.py)")

    # Apply any pending schema migrations
    with db_conn() as conn:
        for col, defn in [
            ("priority",       "INTEGER DEFAULT 10"),
            ("retry_count",    "INTEGER DEFAULT 0"),
            ("max_retries",    "INTEGER DEFAULT 2"),
            ("collector_id",   "INTEGER DEFAULT 0"),
            ("schedule_id",    "INTEGER DEFAULT 0"),
            ("phase_status",   "TEXT DEFAULT '{}'"),
            ("failure_reason", "TEXT"),
            ("label",          "TEXT"),
            ("summary_json",   "TEXT"),
            ("enrichment_source_ids", "TEXT"),
            ("batch_id", "INTEGER DEFAULT 0"),
            ("batch_index", "INTEGER DEFAULT 0"),
            ("batch_total", "INTEGER DEFAULT 0"),
        ]:
            try:
                conn.execute(f"ALTER TABLE scan_jobs ADD COLUMN {col} {defn}")
                log.info("Schema migration: added column scan_jobs.%s", col)
            except Exception:
                pass  # column already exists
        try:
            conn.execute("ALTER TABLE assets ADD COLUMN discovery_sources TEXT DEFAULT '[]'")
            log.info("Schema migration: added column assets.discovery_sources")
        except Exception:
            pass
        try:
            conn.execute("ALTER TABLE assets ADD COLUMN connected_via TEXT DEFAULT ''")
            log.info("Schema migration: added column assets.connected_via")
        except Exception:
            pass
        try:
            conn.execute("ALTER TABLE assets ADD COLUMN ipv6_addrs TEXT DEFAULT '[]'")
            log.info("Schema migration: added column assets.ipv6_addrs")
        except Exception:
            pass
        for col, defn in [
            ("ai_last_confidence", "REAL"),
            ("ai_last_rationale", "TEXT"),
            ("ai_last_applied", "INTEGER DEFAULT 0"),
            ("ai_last_suggested_category", "TEXT"),
            ("ai_last_reason", "TEXT"),
            ("ai_last_attempted", "INTEGER DEFAULT 0"),
            ("ai_last_decision_ts", "DATETIME"),
        ]:
            try:
                conn.execute(f"ALTER TABLE assets ADD COLUMN {col} {defn}")
                log.info("Schema migration: added column assets.%s", col)
            except Exception:
                pass
        if migrate_device_identity_v1(conn):
            log.info("Device identity v1: migration completed (devices + assets.device_id)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_asset_snapshots (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id      INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
                asset_id    INTEGER REFERENCES assets(id) ON DELETE SET NULL,
                ip          TEXT,
                hostname    TEXT,
                category    TEXT,
                vendor      TEXT,
                top_cve     TEXT,
                top_cvss    REAL,
                open_ports  TEXT,
                device_id   INTEGER REFERENCES devices(id),
                captured_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_asset_snapshots_job ON scan_asset_snapshots(job_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_asset_snapshots_asset ON scan_asset_snapshots(asset_id, job_id DESC)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_finding_snapshots (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id      INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
                asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                cve_id      TEXT NOT NULL,
                cvss        REAL,
                severity    TEXT,
                resolved    INTEGER DEFAULT 0,
                captured_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_finding_snapshots_job ON scan_finding_snapshots(job_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_finding_snapshots_asset ON scan_finding_snapshots(asset_id, job_id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_finding_snapshots_asset_cve ON scan_finding_snapshots(asset_id, cve_id, job_id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_batch ON scan_jobs(batch_id, status, id)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT,
                created_by TEXT DEFAULT 'web',
                status TEXT DEFAULT 'active',
                total_targets INTEGER DEFAULT 0,
                pending_targets TEXT DEFAULT '[]',
                exclusions TEXT,
                phases TEXT,
                rate_pps INTEGER DEFAULT 5,
                inter_delay INTEGER DEFAULT 200,
                scan_mode TEXT DEFAULT 'auto',
                profile TEXT DEFAULT 'standard_inventory',
                priority INTEGER DEFAULT 10,
                enrichment_source_ids TEXT,
                auto_split_24 INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_batches_status ON scan_batches(status, id)")

    # Backfill OUI data for existing assets missing vendor info
    with db_conn() as conn:
        recover_stale_running_jobs(conn)
        backfill_oui(conn)
        backfill_proxmox_hostnames(conn)

    retry_timers: dict[int, float] = {}  # job_id → time when ready to retry

    while True:
        try:
            now = time.time()

            # Promote retrying jobs whose timer has elapsed back to queued
            with db_conn() as conn:
                _refresh_scan_batch_statuses(conn)
                fed = _feed_scan_batches(conn, queue_cap=10)
                if fed > 0:
                    log.info("Batch feeder queued %d staged job(s)", fed)
                retrying = conn.execute(
                    "SELECT id FROM scan_jobs WHERE status='retrying'"
                ).fetchall()
                for row in retrying:
                    jid = row["id"]
                    ready_at = retry_timers.get(jid, 0)
                    if now >= ready_at:
                        conn.execute(
                            "UPDATE scan_jobs SET status='queued' WHERE id=?", (jid,)
                        )
                        retry_timers.pop(jid, None)
                        log.info("Job #%d re-queued for retry", jid)

            # Pick next queued job — lowest priority number first, then oldest
            with db_conn() as conn:
                job_row = conn.execute("""
                    SELECT * FROM scan_jobs
                    WHERE status = 'queued'
                      AND COALESCE(collector_id, 0) = 0
                    ORDER BY priority ASC, id ASC
                    LIMIT 1
                """).fetchone()

            if job_row:
                job = dict(job_row)
                retry_num = int(job.get("retry_count") or 0)
                if retry_num > 0:
                    log.info("Picked up job #%d (retry %d) — %s",
                             job["id"], retry_num, job["target_cidr"])
                else:
                    log.info("Picked up job #%d — %s",
                             job["id"], job["target_cidr"])

                try:
                    run_scan(job)
                except Exception as e:
                    log.exception("Job #%d failed: %s", job["id"], e)
                    with db_conn() as conn:
                        if _is_retryable(str(e)):
                            _schedule_retry(conn, job, str(e))
                            retry_timers[job["id"]] = time.time() + RETRY_DELAY_S
                        else:
                            _mark_failed(conn, job["id"], str(e))

        except Exception as e:
            log.exception("Daemon loop error: %s", e)

        time.sleep(POLL_SECS)


if __name__ == "__main__":
    main()
