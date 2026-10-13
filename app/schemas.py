from typing import Literal, Optional

from pydantic import BaseModel, Field, HttpUrl


class Fix(BaseModel):
    summary: str = Field(description="Ringkasan perbaikan, 1-2 kalimat.")
    language: str = Field(description="Bahasa/framework kode patch, mis. python-flask, php-laravel, node-express.")
    code_patch: str = Field(description="Contoh kode sebelum/sesudah atau unified diff. Kosongkan jika tidak cukup konteks.")
    caveats: str = Field(description="Asumsi dan hal yang harus dicek manual sebelum patch dipakai.")


class Finding(BaseModel):
    alert_id: str
    verdict: Literal["true_positive", "likely_false_positive", "needs_manual_verification"]
    confidence: float = Field(ge=0, le=1)
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    cwe: Optional[str] = None
    owasp_top10: Optional[str] = Field(default=None, description="Mis. 'A03:2021 Injection'")
    reasoning: str = Field(description="Alasan verdict, merujuk bukti konkret dari data alert.")
    evidence_quote: str = Field(description="Kutipan pendek (<200 karakter) dari data alert yang mendasari verdict.")
    fix: Optional[Fix] = None
    verification_steps: list[str] = Field(description="Langkah manual aman untuk memverifikasi temuan.")


class Batch(BaseModel):
    findings: list[Finding]


class ScanRequest(BaseModel):
    target_url: HttpUrl
    framework: str = "unknown"
    exclude_patterns: list[str] = []


class Report(BaseModel):
    total_alerts: int
    true_positive: int
    false_positive: int
    needs_review: int
    findings: list[Finding]


class ScanStatus(BaseModel):
    scan_id: str
    state: Literal["queued", "scanning", "analyzing", "done", "failed"] = "queued"
    error: Optional[str] = None
    report: Optional[Report] = None
