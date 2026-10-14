import uuid

from fastapi import BackgroundTasks, FastAPI, HTTPException

from .config import settings
from .guardrails import TargetNotAllowed, assert_target_allowed
from .llm_client import analyze
from .sanitizer import prepare_alerts
from .schemas import Report, ScanRequest, ScanStatus
from .zap_client import run_scan

app = FastAPI(title="DAST-AI Orchestrator")
SCANS: dict[str, ScanStatus] = {}   # produksi: ganti ke database


def pipeline(scan_id: str, req: ScanRequest) -> None:
    st = SCANS[scan_id]
    try:
        st.state = "scanning"
        raw = run_scan(
            target=str(req.target_url),
            extra_excludes=req.exclude_patterns,
            scan_mode=req.scan_mode,
            custom_headers=req.custom_headers,
        )

        st.state = "analyzing"
        cleaned = prepare_alerts(raw)
        findings = analyze(cleaned, req.framework)

        st.report = Report(
            total_alerts=len(cleaned),
            true_positive=sum(f.verdict == "true_positive" for f in findings),
            false_positive=sum(f.verdict == "likely_false_positive" for f in findings),
            needs_review=sum(f.verdict == "needs_manual_verification" for f in findings),
            findings=findings,
        )
        st.state = "done"
    except Exception as e:  # noqa: BLE001
        st.state, st.error = "failed", str(e)


@app.post("/scans", response_model=ScanStatus, status_code=202)
def create_scan(req: ScanRequest, bg: BackgroundTasks):
    try:
        assert_target_allowed(str(req.target_url))
    except TargetNotAllowed as e:
        raise HTTPException(403, str(e))
    scan_id = uuid.uuid4().hex[:12]
    SCANS[scan_id] = ScanStatus(scan_id=scan_id)
    bg.add_task(pipeline, scan_id, req)
    return SCANS[scan_id]


@app.get("/health")
def health():
    return {
        "status": "ok",
        "environment": settings.environment,
        "zap_url": settings.zap_url,
        "llm_configured": bool(settings.llm_api_key),
    }


@app.get("/scans", response_model=list[ScanStatus])
def list_scans():
    return list(SCANS.values())


@app.get("/scans/{scan_id}", response_model=ScanStatus)
def get_scan(scan_id: str):
    if scan_id not in SCANS:
        raise HTTPException(404, "scan tidak ditemukan")
    return SCANS[scan_id]

