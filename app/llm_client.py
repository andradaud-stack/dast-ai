import json
import logging
from pathlib import Path

import anthropic

from .config import settings
from .sanitizer import sanitize_dict_or_str
from .schemas import Batch, Finding

logger = logging.getLogger(__name__)

SYSTEM = (Path(__file__).parent / "prompts" / "system_prompt.md").read_text(encoding="utf-8")
CHUNK = 15


def _get_client() -> anthropic.Anthropic | None:
    """Mengembalikan client Anthropic jika API key valid dikonfigurasi."""
    key = settings.llm_api_key.strip()
    if not key or key.startswith("ganti-") or key == "sk-ant-...":
        return None
    try:
        return anthropic.Anthropic(api_key=key)
    except Exception as e:
        logger.warning("Gagal menginisialisasi client Anthropic: %s", e)
        return None


def _fallback_findings(alerts: list[dict]) -> list[Finding]:
    """Menghasilkan temuan triage fallback aman jika LLM API key tidak tersedia."""
    out = []
    for a in alerts:
        risk = (a.get("risk") or "info").lower()
        if risk == "informational":
            risk = "info"
        if risk not in ("critical", "high", "medium", "low", "info"):
            risk = "info"

        out.append(
            Finding(
                alert_id=a.get("alert_id") or "A001",
                verdict="needs_manual_verification",
                confidence=0.5,
                severity=risk,
                title=a.get("name") or a.get("title") or "Security Alert",
                cwe=str(a.get("cwe")) if a.get("cwe") else None,
                reasoning="Analisis otomatis LLM tidak aktif (fallback mode). Verifikasi bukti teknis ZAP secara manual.",
                evidence_quote=(a.get("evidence") or "")[:200],
                verification_steps=["Periksa parameter dan request pada target untuk mengonfirmasi temuan."],
            )
        )
    return out


def _analyze_chunk(client: anthropic.Anthropic, alerts: list[dict], framework: str) -> list[Finding]:
    """Menganalisis chunk alert dengan proteksi input dan tool use."""
    safe_alerts = [sanitize_dict_or_str(a) for a in alerts]
    payload = {"framework": framework, "alerts": safe_alerts}
    user = (
        "<scan_data>\n" + json.dumps(payload, ensure_ascii=False) + "\n</scan_data>\n"
        "Analisis semua alert di atas, lalu panggil tool submit_report."
    )
    try:
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
            timeout=45.0,
        )
        block = next(b for b in resp.content if b.type == "tool_use")
        return Batch.model_validate(block.input).findings
    except Exception as e:
        logger.warning("Gagal menjalankan triase LLM pada chunk: %s", e)
        return _fallback_findings(alerts)


def analyze(alerts: list[dict], framework: str) -> list[Finding]:
    """
    Menjalankan triase LLM sebagai lapisan tambahan.
    Jika LLM key belum dikonfigurasi, mengembalikan temuan fallback manual triage.
    """
    if not alerts:
        return []

    client = _get_client()
    if not client:
        logger.info("LLM_API_KEY tidak dikonfigurasi. Menggunakan fallback triage.")
        return _fallback_findings(alerts)

    findings: list[Finding] = []
    for i in range(0, len(alerts), CHUNK):
        chunk_findings = _analyze_chunk(client, alerts[i:i + CHUNK], framework)
        findings.extend(chunk_findings)
    return findings
