import json
from pathlib import Path

import anthropic

from .config import settings
from .schemas import Batch, Finding

SYSTEM = (Path(__file__).parent / "prompts" / "system_prompt.md").read_text(encoding="utf-8")
CHUNK = 15

RISK_TO_SEVERITY = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}


def get_client() -> anthropic.Anthropic:
    return anthropic.Anthropic(api_key=settings.llm_api_key)


def _fallback_triage(alerts: list[dict], framework: str) -> list[Finding]:
    """Fallback triage saat LLM_API_KEY tidak dikonfigurasi (mis. offline/CI test)."""
    findings: list[Finding] = []
    for a in alerts:
        risk_raw = a.get("risk", "Low")
        severity = RISK_TO_SEVERITY.get(risk_raw, "info")
        name = a.get("name") or "Security Alert"
        url = a.get("url") or ""
        evidence = a.get("evidence") or a.get("attack") or "Tidak ada evidence detail"
        cwe_val = str(a.get("cwe")) if a.get("cwe") else None

        findings.append(
            Finding(
                alert_id=a.get("alert_id", "A000"),
                verdict="needs_manual_verification",
                confidence=0.5,
                severity=severity,  # type: ignore[arg-type]
                title=name,
                cwe=cwe_val,
                owasp_top10=None,
                reasoning="Triase rule-based fallback: LLM_API_KEY belum dikonfigurasi sehingga evaluasi otomatis LLM dinonaktifkan.",
                evidence_quote=evidence[:180],
                verification_steps=[
                    f"Periksa secara manual endpoint: {url}",
                    f"Validasi apakah parameter '{a.get('param')}' memiliki sanitasi input yang memadai pada framework {framework}.",
                ],
            )
        )
    return findings


def _analyze_chunk(alerts: list[dict], framework: str) -> list[Finding]:
    client = get_client()
    payload = {"framework": framework, "alerts": alerts}
    user = (
        "<scan_data>\n" + json.dumps(payload, ensure_ascii=False) + "\n</scan_data>\n"
        "Analisis semua alert di atas, lalu panggil tool submit_report."
    )
    resp = client.messages.create(
        model=settings.llm_model,
        max_tokens=8000,
        system=SYSTEM,
        tools=[{
            "name": "submit_report",
            "description": "Kirim hasil triase terstruktur.",
            "input_schema": Batch.model_json_schema(),
        }],
        tool_choice={"type": "tool", "name": "submit_report"},
        messages=[{"role": "user", "content": user}],
    )
    block = next(b for b in resp.content if b.type == "tool_use")
    return Batch.model_validate(block.input).findings  # validasi ketat -> tolak output cacat


def analyze(alerts: list[dict], framework: str) -> list[Finding]:
    if not alerts:
        return []
    if not settings.llm_api_key:
        return _fallback_triage(alerts, framework)
    findings: list[Finding] = []
    for i in range(0, len(alerts), CHUNK):
        findings += _analyze_chunk(alerts[i:i + CHUNK], framework)
    return findings
