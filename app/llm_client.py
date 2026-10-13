import json
from pathlib import Path

import anthropic

from .config import settings
from .schemas import Batch, Finding

SYSTEM = (Path(__file__).parent / "prompts" / "system_prompt.md").read_text(encoding="utf-8")
client = anthropic.Anthropic(api_key=settings.llm_api_key)
CHUNK = 15


def _analyze_chunk(alerts: list[dict], framework: str) -> list[Finding]:
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
    findings: list[Finding] = []
    for i in range(0, len(alerts), CHUNK):
        findings += _analyze_chunk(alerts[i:i + CHUNK], framework)
    return findings
