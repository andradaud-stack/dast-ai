from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.config import settings
from app.schemas import TargetHealth
from app.zap_client import (
    check_target_health,
    check_zap_connectivity,
    execute_scan,
)


def test_check_target_health_accessible():
    mock_resp = MagicMock(status_code=200, url="http://localhost:8000/", text="Welcome")
    mock_resp.headers = {"content-type": "text/html"}

    with patch("httpx.Client.get", return_value=mock_resp):
        health = check_target_health("http://localhost:8000")
        assert health.accessible is True
        assert health.is_protected is False
        assert health.status_code == 200


def test_check_target_health_vercel_protection():
    mock_resp = MagicMock(
        status_code=401,
        url="https://preview.dast-test.vercel.app/",
        text="Vercel Deployment Protection Authentication Required",
    )
    mock_resp.headers = {"x-vercel-challenge": "1"}

    with patch("httpx.Client.get", return_value=mock_resp):
        health = check_target_health("https://preview.dast-test.vercel.app")
        assert health.accessible is False
        assert health.is_protected is True
        assert health.protection_type == "vercel_challenge"
        assert "Vercel Deployment Protection" in health.diagnostic_message


def test_check_target_health_http_auth():
    mock_resp = MagicMock(status_code=401, url="http://localhost:8000/admin", text="Unauthorized")
    mock_resp.headers = {"www-authenticate": "Basic realm=Admin"}

    with patch("httpx.Client.get", return_value=mock_resp):
        health = check_target_health("http://localhost:8000/admin")
        assert health.accessible is False
        assert health.is_protected is True
        assert health.protection_type == "http_auth"


def test_check_target_health_waf_forbidden():
    mock_resp = MagicMock(status_code=403, url="http://localhost:8000/secret", text="Forbidden")
    mock_resp.headers = {}

    with patch("httpx.Client.get", return_value=mock_resp):
        health = check_target_health("http://localhost:8000/secret")
        assert health.accessible is False
        assert health.is_protected is True
        assert health.protection_type == "waf_blocked"


def test_check_target_health_out_of_scope_redirect():
    mock_resp = MagicMock(status_code=302, url="http://localhost:8000/login", text="")
    mock_resp.headers = {"location": "https://external-auth.thirdparty.com/login"}

    with patch("httpx.Client.get", return_value=mock_resp):
        health = check_target_health("http://localhost:8000/login")
        assert health.accessible is False
        assert health.is_redirected is True
        assert health.redirect_in_scope is False
        assert health.protection_type == "redirect_out_of_scope"


def test_check_target_health_connection_error():
    with patch("httpx.Client.get", side_effect=httpx.ConnectError("Connection refused")):
        health = check_target_health("http://localhost:8000")
        assert health.accessible is False
        assert "Gagal menghubungkan" in health.diagnostic_message


def test_check_zap_connectivity_failed(monkeypatch):
    monkeypatch.setattr(settings, "zap_url", "http://127.0.0.1:59999")
    # Port 59999 tidak aktif -> harus return False tanpa unhandled crash
    assert check_zap_connectivity() is False


def test_execute_scan_blocked_early():
    """Jika target health mengindikasikan blocked, scan harus berhenti sebelum ZAP dijalankan."""
    blocked_health = TargetHealth(
        accessible=False,
        is_protected=True,
        protection_type="vercel_challenge",
        diagnostic_message="Target terlindungi Vercel",
    )
    with patch("app.zap_client.check_target_health", return_value=blocked_health):
        res = execute_scan("http://localhost:8000", scan_mode="passive")
        assert res.verdict_status == "blocked"
        assert len(res.limitations) > 0
        assert "Scan diblokir oleh proteksi target" in res.limitations[0]


def test_execute_scan_passive_mode_skips_active_scan():
    """Mode passive harus menjalankan spider & pscan tetapi melompati active scanner."""
    mock_health = TargetHealth(accessible=True, status_code=200, diagnostic_message="OK")
    mock_zap = MagicMock()
    mock_zap.spider.scan.return_value = "1"
    mock_zap.spider.status.return_value = 100
    mock_zap.spider.results.return_value = ["http://localhost:8000/", "http://localhost:8000/about"]
    mock_zap.pscan.records_to_scan = 0
    mock_zap.core.alerts.return_value = [
        {"pluginId": "10001", "alert": "Missing Anti-clickjacking Header", "risk": "Low", "url": "http://localhost:8000/"}
    ]

    with patch("app.zap_client.check_target_health", return_value=mock_health), \
         patch("app.zap_client.check_zap_connectivity", return_value=True), \
         patch("app.zap_client._zap", return_value=mock_zap):

        res = execute_scan("http://localhost:8000", scan_mode="passive")

        assert res.verdict_status == "completed"
        assert res.coverage.spider_status == "completed"
        assert res.coverage.active_scan_status == "skipped_passive_mode"
        # ascan.scan tidak boleh dipanggil sama sekali!
        mock_zap.ascan.scan.assert_not_called()
        assert len(res.technical_alerts) == 1
        assert res.technical_alerts[0].name == "Missing Anti-clickjacking Header"
        assert any("TIDAK dijalankan karena scanner berada dalam mode 'passive'" in lim for lim in res.limitations)


def test_check_target_health_tls_error():
    """Memverifikasi bahwa kegagalan TLS/SSL menandai target tidak aman (Priority 2)."""
    import ssl
    with patch("httpx.Client.get", side_effect=ssl.SSLError("certificate verify failed")):
        health = check_target_health("https://untrusted-cert.example.com")
        assert health.accessible is False
        assert health.is_protected is True
        assert health.protection_type == "tls_error"
        assert "Verifikasi TLS/SSL gagal" in health.diagnostic_message


def test_zap_replacer_failure_stops_scan_without_secret_leak():
    """Memverifikasi bahwa jika replacer gagal mengisolasi header rahasia, scan berhenti dan secret tidak bocor (Priority 1)."""
    mock_health = TargetHealth(accessible=True, status_code=200, diagnostic_message="OK")
    mock_zap = MagicMock()
    mock_zap.replacer.add_rule.side_effect = Exception("ZAP internal replacer crash")

    secret_val = "super-secret-bypass-val-999"

    with patch("app.zap_client.check_target_health", return_value=mock_health), \
         patch("app.zap_client.check_zap_connectivity", return_value=True), \
         patch("app.zap_client._zap", return_value=mock_zap):

        with pytest.raises(RuntimeError) as exc_info:
            execute_scan(
                target="http://localhost:8000",
                scan_mode="passive",
                custom_headers={"x-vercel-protection-bypass": secret_val},
            )

        err_msg = str(exc_info.value)
        assert "Gagal mengonfigurasi isolasi header pada pemindai ZAP" in err_msg
        assert secret_val not in err_msg  # Secret TIDAK BOLEH bocor dalam pesan error!


def test_coverage_metrics_separates_discovered_and_tested_endpoints():
    """Memverifikasi bahwa URL out-of-scope dipisahkan ke urls_rejected_by_scope dan tidak dihitung sebagai tested endpoints (Priority 3)."""
    mock_health = TargetHealth(accessible=True, status_code=200, diagnostic_message="OK")
    mock_zap = MagicMock()
    mock_zap.spider.scan.return_value = "1"
    mock_zap.spider.status.return_value = 100
    # Spider menemukan URL in-scope dan out-of-scope
    mock_zap.spider.results.return_value = [
        "http://localhost:8000/dashboard",
        "http://localhost:8000/profile",
        "http://evil.com/leak",
        "http://localhost:9000/wrong-port",
    ]
    mock_zap.pscan.records_to_scan = 0
    mock_zap.core.alerts.return_value = []

    with patch("app.zap_client.check_target_health", return_value=mock_health), \
         patch("app.zap_client.check_zap_connectivity", return_value=True), \
         patch("app.zap_client._zap", return_value=mock_zap):

        res = execute_scan("http://localhost:8000", scan_mode="passive")

        # In-scope
        assert "http://localhost:8000/dashboard" in res.coverage.urls_requested
        assert "/dashboard" in res.coverage.endpoints_tested

        # Out-of-scope harus ditolak dan dicatat terpisah
        assert "http://evil.com/leak" in res.coverage.urls_rejected_by_scope
        assert "http://localhost:9000/wrong-port" in res.coverage.urls_rejected_by_scope
        assert res.coverage.total_urls_rejected_by_scope == 2
        assert "/leak" not in res.coverage.endpoints_tested


def test_invalid_exclusion_pattern_rejected():
    """Memverifikasi bahwa pola regex exclusion yang tidak valid ditolak sebelum scan dimulai (Priority 5)."""
    with pytest.raises(ValueError, match="bukan regex valid"):
        execute_scan(
            target="http://localhost:8000",
            extra_excludes=["[unclosed-regex("],
        )

