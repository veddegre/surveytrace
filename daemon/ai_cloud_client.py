"""
SurveyTrace — OpenAI / Anthropic / Google Gemini / Open WebUI chat HTTP (stdlib only).
Used by scanner_daemon when ai_provider is not ollama.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def _openwebui_base_ok(base: str) -> bool:
    b = (base or "").strip().rstrip("/")
    if not b or len(b) > 500:
        return False
    u = urllib.parse.urlparse(b)
    return u.scheme in ("http", "https") and bool(u.netloc)


def _max_out_toks(num_predict: int) -> int:
    if num_predict <= 0:
        return 2048
    return max(256, min(8192, int(num_predict)))


def _post_json(
    url: str, headers: dict[str, str], body: dict[str, Any], timeout_s: float
) -> tuple[int, str, str]:
    data = json.dumps(body).encode("utf-8")
    hdrs = {**headers, "Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            code = int(getattr(resp, "status", None) or 200)
            return code, resp.read().decode("utf-8", errors="replace"), ""
    except urllib.error.HTTPError as e:
        try:
            raw = e.read().decode("utf-8", errors="replace")
        except Exception:
            raw = ""
        return int(e.code), raw, f"http_{e.code}"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        return 0, "", str(e)[:200]


def cloud_chat_completion(
    provider: str,
    model: str,
    prompt: str,
    timeout_s: float,
    temperature: float,
    num_predict: int,
    openai_key: str,
    anthropic_key: str,
    gemini_key: str,
    openwebui_base: str = "",
    openwebui_key: str = "",
) -> tuple[str, str]:
    """Return (text, err). err empty on success."""
    provider = (provider or "").strip().lower()
    model = (model or "").strip()
    if not model:
        return "", "empty_model"
    mx = _max_out_toks(num_predict)
    temp = max(0.0, min(2.0, float(temperature)))

    if provider == "openai":
        k = (openai_key or "").strip()
        if not k:
            return "", "missing_openai_api_key"
        body: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temp,
            "max_tokens": mx,
        }
        code, raw, err = _post_json(
            "https://api.openai.com/v1/chat/completions",
            {"Authorization": "Bearer " + k},
            body,
            timeout_s,
        )
        if err or code >= 400:
            return "", err or raw[:300] or f"http_{code}"
        try:
            doc = json.loads(raw)
        except Exception:
            return "", "bad_json"
        if not isinstance(doc, dict):
            return "", "bad_shape"
        txt = str((doc.get("choices") or [{}])[0].get("message", {}).get("content") or "").strip()
        return (txt, "") if txt else ("", "openai_empty_content")

    if provider == "openwebui":
        b = (openwebui_base or "").strip().rstrip("/")
        k = (openwebui_key or "").strip()
        if not _openwebui_base_ok(b):
            return "", "missing_or_invalid_openwebui_base_url"
        if not k:
            return "", "missing_openwebui_api_key"
        body = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temp,
            "max_tokens": mx,
        }
        code, raw, err = _post_json(
            b + "/api/chat/completions",
            {"Authorization": "Bearer " + k},
            body,
            timeout_s,
        )
        if err or code >= 400:
            return "", err or raw[:300] or f"http_{code}"
        try:
            doc = json.loads(raw)
        except Exception:
            return "", "bad_json"
        if not isinstance(doc, dict):
            return "", "bad_shape"
        txt = str((doc.get("choices") or [{}])[0].get("message", {}).get("content") or "").strip()
        return (txt, "") if txt else ("", "openwebui_empty_content")

    if provider == "anthropic":
        k = (anthropic_key or "").strip()
        if not k:
            return "", "missing_anthropic_api_key"
        body = {
            "model": model,
            "max_tokens": mx,
            "temperature": temp,
            "messages": [{"role": "user", "content": prompt}],
        }
        code, raw, err = _post_json(
            "https://api.anthropic.com/v1/messages",
            {
                "x-api-key": k,
                "anthropic-version": "2023-06-01",
            },
            body,
            timeout_s,
        )
        if err or code >= 400:
            return "", err or raw[:300] or f"http_{code}"
        try:
            doc = json.loads(raw)
        except Exception:
            return "", "bad_json"
        if not isinstance(doc, dict):
            return "", "bad_shape"
        parts = doc.get("content") or []
        txt = ""
        if isinstance(parts, list):
            for b in parts:
                if isinstance(b, dict) and b.get("type") == "text":
                    txt += str(b.get("text") or "")
        txt = txt.strip()
        return (txt, "") if txt else ("", "anthropic_empty_content")

    if provider == "google":
        k = (gemini_key or "").strip()
        if not k:
            return "", "missing_gemini_api_key"
        mid = urllib.parse.quote(model, safe="")
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            + mid
            + ":generateContent?key="
            + urllib.parse.quote(k, safe="")
        )
        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": temp, "maxOutputTokens": mx},
        }
        code, raw, err = _post_json(url, {}, body, timeout_s)
        if err or code >= 400:
            return "", err or raw[:300] or f"http_{code}"
        try:
            doc = json.loads(raw)
        except Exception:
            return "", "bad_json"
        if not isinstance(doc, dict):
            return "", "bad_shape"
        if doc.get("error"):
            em = doc["error"]
            if isinstance(em, dict):
                em = str(em.get("message") or em)
            return "", str(em)[:300]
        parts = ((doc.get("candidates") or [{}])[0].get("content") or {}).get("parts") or []
        txt = ""
        if isinstance(parts, list):
            for pt in parts:
                if isinstance(pt, dict):
                    txt += str(pt.get("text") or "")
        txt = txt.strip()
        return (txt, "") if txt else ("", "gemini_empty_content")

    return "", "unsupported_cloud_provider"
