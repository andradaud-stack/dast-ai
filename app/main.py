import collections
import logging
import secrets
import threading
from typing import Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import settings
from .guardrails import TargetNotAllowed, assert_target_allowed
from .llm_client import analyze
from .schemas import (
    ScanReport,
    ScanRequest,
    ScanStatus,
)
from .zap_client import check_zap_connectivity, execute_scan

logger = logging.getLogger(__name__)

app = FastAPI(
    title="DAST-AI Enterprise Orchestrator",
    description="Sistem orkestrasi pemindaian keamanan dinamis (DAST) berbasis OWASP ZAP dan LLM Triage.",
    version="1.0.0",
)

# Penyimpanan in-memory thread-safe dengan batas kapasitas terdefinisi (mencegah memory leak)
_store_lock = threading.Lock()
SCANS: collections.OrderedDict[str, ScanStatus] = collections.OrderedDict()

# Semaphore pembatas beban scan konkuren
_scan_semaphore = threading.Semaphore(settings.max_concurrent_scans)

# Skema keamanan API
security_bearer = HTTPBearer(auto_error=False)


def verify_api_auth(credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)) -> None:
    """
    Memvalidasi autentikasi API.
    Jika api_auth_token di-set di environment/config, token Bearer wajib disertakan.
    """
    expected_token = settings.api_auth_token.strip()
    if not expected_token:
        # Jika belum diatur dan lingkungan local/staging, izinkan akses
        return

    if not credentials or credentials.credentials != expected_token:
        raise HTTPException(
            status_code=401,
            detail="Akses tidak diotorisasi. Token API Bearer diperlukan.",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _store_scan(scan_id: str, status: ScanStatus) -> None:
    with _store_lock:
        if len(SCANS) >= settings.max_stored_scans:
            SCANS.popitem(last=False)
        SCANS[scan_id] = status


def _get_scan(scan_id: str) -> Optional[ScanStatus]:
    with _store_lock:
        return SCANS.get(scan_id)


def pipeline(scan_id: str, req: ScanRequest) -> None:
    """Pipeline asynchronous yang mengeksekusi scanning dan analisis laporan."""
    st = _get_scan(scan_id)
    if not st:
        return

    if not _scan_semaphore.acquire(blocking=True, timeout=120):
        st.state = "failed"
        st.error = "Scan dibatalkan: Server terlalu sibuk (batas scan konkuren tercapai)."
        return

    try:
        def update_state(state_name: str):
            st.state = state_name

        result = execute_scan(
            target=str(req.target_url),
            scan_mode=req.scan_mode,
            extra_excludes=req.exclude_patterns,
            custom_headers=req.custom_headers,
            scan_policy=req.active_scan_policy,
            progress_callback=update_state,
        )

        if result.verdict_status in ("blocked", "inconclusive"):
            st.state = result.verdict_status
            st.report = ScanReport(
                scan_id=scan_id,
                target_url=str(req.target_url),
                scan_mode=req.scan_mode,
                verdict_status=result.verdict_status,
                target_health=result.target_health,
                coverage=result.coverage,
                total_technical_alerts=0,
                technical_alerts=[],
                ai_triage=[],
                summary={"high": 0, "medium": 0, "low": 0, "info": 0},
                limitations=result.limitations,
            )
            return

        st.state = "analyzing"
        cleaned_dicts = [a.model_dump() for a in result.technical_alerts]
        findings = analyze(cleaned_dicts, req.framework)

        summary = {
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high": sum(1 for a in result.technical_alerts if a.risk.lower() == "high"),
            "medium": sum(1 for a in result.technical_alerts if a.risk.lower() == "medium"),
            "low": sum(1 for a in result.technical_alerts if a.risk.lower() == "low"),
            "info": sum(1 for a in result.technical_alerts if a.risk.lower() in ("informational", "info")),
            "true_positive": sum(1 for f in findings if f.verdict == "true_positive"),
            "likely_false_positive": sum(1 for f in findings if f.verdict == "likely_false_positive"),
            "needs_manual_verification": sum(1 for f in findings if f.verdict == "needs_manual_verification"),
        }

        st.report = ScanReport(
            scan_id=scan_id,
            target_url=str(req.target_url),
            scan_mode=req.scan_mode,
            verdict_status=result.verdict_status,
            target_health=result.target_health,
            coverage=result.coverage,
            total_technical_alerts=len(result.technical_alerts),
            technical_alerts=result.technical_alerts,
            ai_triage=findings,
            summary=summary,
            limitations=result.limitations,
        )
        st.state = "done"

    except Exception as e:
        logger.exception("Kesalahan internal saat menjalankan pipeline scan %s: %s", scan_id, e)
        st.state = "failed"
        st.error = str(e)
    finally:
        _scan_semaphore.release()


@app.get("/health")
def health_check():
    """Endpoint health check yang memeriksa status server dan koneksi ZAP."""
    zap_ok = check_zap_connectivity()
    return {
        "status": "ok",
        "zap_connected": zap_ok,
        "zap_url": settings.zap_url,
        "environment": settings.environment,
        "llm_configured": bool(settings.llm_api_key),
        "default_scan_mode": settings.default_scan_mode,
        "active_scans_capacity": settings.max_concurrent_scans,
    }


@app.post("/scans", response_model=ScanStatus, status_code=202, dependencies=[Depends(verify_api_auth)])
def create_scan(req: ScanRequest, bg: BackgroundTasks):
    """
    Memicu proses pemindaian DAST baru.
    - Validasi target melalui guardrails ketat (SSRF & Scope Enforcement).
    - Memulai background pipeline sesuai scan_mode ('passive', 'active', atau 'full').
    """
    target_str = str(req.target_url)
    try:
        assert_target_allowed(target_str)
    except TargetNotAllowed as e:
        raise HTTPException(status_code=403, detail=str(e))

    scan_id = secrets.token_hex(16)
    scan_status = ScanStatus(scan_id=scan_id, state="queued")

    _store_scan(scan_id, scan_status)
    bg.add_task(pipeline, scan_id, req)
    return scan_status


@app.get("/scans/{scan_id}", response_model=ScanStatus, dependencies=[Depends(verify_api_auth)])
def get_scan(scan_id: str):
    """Melihat status terkini dan laporan hasil scan berdasarkan scan_id."""
    status = _get_scan(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail="scan tidak ditemukan")
    return status


@app.get("/scans", response_model=list[ScanStatus], dependencies=[Depends(verify_api_auth)])
def list_scans():
    """Melihat daftar riwayat scan terkini."""
    with _store_lock:
        return list(SCANS.values())
