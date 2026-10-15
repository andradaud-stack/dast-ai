import re
from urllib.parse import urlparse

from .config import settings

RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
MAX_ALERTS = 50

_SECRETS = [
    # Private Key
    (re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----"), "[PRIVATE_KEY]"),
    # JWT Tokens
    (re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+"), "[JWT]"),
    # Vercel Deployment Protection bypass secrets
    (re.compile(r"(?i)(x-vercel-protection-bypass|x-vercel-set-bypass-cookie)([\"'=:\s]+)[\w\-\.]{6,}"),
     r"\1\2[REDACTED]"),
    # Bearer, Basic Auth, Secrets, Passwords, API Keys, Session Tokens
    (re.compile(r"(?i)(basic\s+)[a-zA-Z0-9+/=]{10,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(bearer|token|api[_-]?key|secret|passwd|password|session(?:id)?|csrf[_-]?token)([\"'=:\s]+)[\w\-\.]{6,}"),
     r"\1\2[REDACTED]"),
    # URL Query parameter secrets
    (re.compile(r"(?i)([?&](?:token|key|api_key|apikey|secret|auth|passwd|password|access_token)=)[^&\s]+"),
     r"\1[REDACTED]"),
    # Emails
    (re.compile(r"[\w\.+-]+@[\w-]+\.[\w\.-]+"), "[EMAIL]"),
]


def _clean(text: str | None, limit: int = 500) -> str:
    """Sanitasi string dari data sensitif dan batasi panjang karakter."""
    text = text or ""

    # Sensor secret literal dari settings jika dikonfigurasi (misal token Vercel, ZAP key, LLM key)
    configured_secrets = [
        getattr(settings, "vercel_bypass_secret", ""),
        getattr(settings, "vercel_protection_bypass_secret", ""),
        getattr(settings, "zap_api_key", ""),
        getattr(settings, "llm_api_key", ""),
        getattr(settings, "api_auth_token", ""),
    ]
    for sec in configured_secrets:
        if sec and len(sec) >= 6 and sec in text:
            text = text.replace(sec, "[REDACTED_SECRET]")

    for rx, repl in _SECRETS:
        text = rx.sub(repl, text)
    return text[:limit]


def sanitize_dict_or_str(data: dict | str | None) -> dict | str | None:
    """Sanitasi struktur data dictionary atau string dari secrets."""
    if data is None:
        return None
    if isinstance(data, str):
        return _clean(data, 1000)
    if isinstance(data, dict):
        return {k: _clean(str(v), 1000) if isinstance(v, str) else v for k, v in data.items()}
    return data


def prepare_alerts(raw: list[dict]) -> list[dict]:
    """
    Menyiapkan alert mentah dari ZAP:
    - Melakukan deduplikasi cerdas tanpa menghilangkan temuan pada parameter atau attack berbeda
    - Melakukan sanitasi kredensial, JWT, dan rahasia
    - Mengurutkan berdasarkan tingkat keparahan risiko
    """
    seen, out = set(), []
    for a in sorted(raw, key=lambda x: RISK_ORDER.get(x.get("risk"), 9)):
        url = a.get("url", "")
        path = urlparse(url).path
        method = a.get("method", "")
        param = a.get("param", "")
        plugin_id = a.get("pluginId", "")
        attack = a.get("attack", "")

        key = (plugin_id, method, param, path, attack[:50] if attack else "")
        if key in seen:
            continue
        seen.add(key)

        out.append({
            "alert_id": f"A{len(out)+1:03d}",
            "plugin_id": str(plugin_id),
            "name": a.get("alert") or a.get("name") or "Unnamed Alert",
            "risk": a.get("risk", "Informational"),
            "zap_confidence": a.get("confidence", "Medium"),
            "cwe": str(a.get("cweid") or a.get("cwe") or ""),
            "wasc": str(a.get("wascid") or a.get("wasc") or ""),
            "method": method,
            "url": _clean(url, 300),
            "param": param,
            "attack": _clean(attack, 200),
            "evidence": _clean(a.get("evidence", ""), 300),
            "zap_description": _clean(a.get("description", ""), 400),
            "solution": _clean(a.get("solution", ""), 300),
            "reference": _clean(a.get("reference", ""), 300),
            "source": a.get("source", "zap"),
        })
        if len(out) >= MAX_ALERTS:
            break
    return out
