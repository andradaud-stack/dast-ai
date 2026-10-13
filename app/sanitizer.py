import re
from urllib.parse import urlparse

RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
MAX_ALERTS = 50

_SECRETS = [
    (re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+"), "[JWT]"),
    (re.compile(r"(?i)(bearer|token|api[_-]?key|secret|passwd|password|session(?:id)?)([\"'=:\s]+)[\w\-\.]{8,}"),
     r"\1\2[REDACTED]"),
    (re.compile(r"[\w\.+-]+@[\w-]+\.[\w\.-]+"), "[EMAIL]"),
]


def _clean(text: str, limit: int) -> str:
    text = text or ""
    for rx, repl in _SECRETS:
        text = rx.sub(repl, text)
    return text[:limit]


def prepare_alerts(raw: list[dict]) -> list[dict]:
    seen, out = set(), []
    for a in sorted(raw, key=lambda x: RISK_ORDER.get(x.get("risk"), 9)):
        path = urlparse(a.get("url", "")).path
        key = (a.get("pluginId"), a.get("method"), a.get("param"), path)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "alert_id": f"A{len(out)+1:03d}",
            "name": a.get("alert"),
            "risk": a.get("risk"),
            "zap_confidence": a.get("confidence"),
            "cwe": a.get("cweid"),
            "method": a.get("method"),
            "url": _clean(a.get("url", ""), 300),
            "param": a.get("param"),
            "attack": _clean(a.get("attack", ""), 200),
            "evidence": _clean(a.get("evidence", ""), 300),
            "zap_description": _clean(a.get("description", ""), 400),
        })
        if len(out) >= MAX_ALERTS:
            break
    return out
