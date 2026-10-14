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
    scan_mode: Literal["passive", "active", "full"] = "passive"
    framework: str = "unknown"
    exclude_patterns: list[str] = Field(default_factory=list)
    custom_headers: dict[str, str] = Field(default_factory=dict)
    active_scan_policy: Optional[str] = None


class TargetHealth(BaseModel):
    accessible: bool = False
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    is_redirected: bool = False
    redirect_in_scope: bool = True
    is_protected: bool = False
    protection_type: Optional[str] = None   # "vercel_challenge", "http_auth", "login_wall", "waf_blocked", None
    diagnostic_message: Optional[str] = None


class CoverageMetrics(BaseModel):
    urls_discovered: list[str] = Field(default_factory=list)
    total_urls_discovered: int = 0
    urls_requested: list[str] = Field(default_factory=list)
    total_urls_requested: int = 0
    endpoints_tested: list[str] = Field(default_factory=list)
    total_endpoints_tested: int = 0
    urls_rejected_by_scope: list[str] = Field(default_factory=list)
    total_urls_rejected_by_scope: int = 0
    spider_status: str = "not_run"
    passive_scan_status: str = "not_run"
    active_scan_status: str = "not_run"
    active_scan_rules_run: int = 0
    requests_succeeded: int = 0
    requests_failed: int = 0
    requests_blocked: int = 0
    duration_seconds: dict[str, float] = Field(default_factory=dict)
    untested_checks: list[str] = Field(default_factory=list)
    limitations_disclaimer: str = ""


class TechnicalAlert(BaseModel):
    alert_id: str
    plugin_id: str = ""
    name: str
    risk: str
    confidence: str
    cwe: Optional[str] = None
    wasc: Optional[str] = None
    url: str
    method: str
    param: Optional[str] = None
    attack: Optional[str] = None
    evidence: Optional[str] = None
    zap_description: Optional[str] = None
    solution: Optional[str] = None
    reference: Optional[str] = None
    source: str = "zap"


class ScanReport(BaseModel):
    scan_id: str
    target_url: str
    scan_mode: Literal["passive", "active", "full"]
    verdict_status: Literal["completed", "inconclusive", "blocked", "failed"]
    target_health: TargetHealth
    coverage: CoverageMetrics
    total_technical_alerts: int = 0
    technical_alerts: list[TechnicalAlert] = Field(default_factory=list)
    ai_triage: list[Finding] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)


# Alias untuk kompatibilitas ke belakang
Report = ScanReport


class ScanStatus(BaseModel):
    scan_id: str
    state: Literal[
        "queued",
        "preflight",
        "spidering",
        "passive_scanning",
        "active_scanning",
        "analyzing",
        "done",
        "inconclusive",
        "blocked",
        "failed",
    ] = "queued"
    error: Optional[str] = None
    report: Optional[ScanReport] = None
