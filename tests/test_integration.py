from unittest.mock import MagicMock, patch
import pytest

from app.config import settings
from app.schemas import ScanRequest
from app.zap_client import check_target_health, check_zap_connectivity, execute_scan
from tests.fixture_app import FixtureServer, FixtureState


@pytest.fixture(scope="module")
def fixture_server():
    server = FixtureServer()
    server.start()
    yield server
    server.stop()


def test_fixture_live_accessible(fixture_server):
    """Memverifikasi fixture app lokal dapat diakses secara live oleh scanner pre-flight."""
    health = check_target_health(fixture_server.base_url)
    assert health.accessible is True
    assert health.status_code == 200
    assert health.is_protected is False


def test_fixture_live_http_auth_detected(fixture_server):
    """Memverifikasi rute /admin/secret terdeteksi sebagai HTTP Basic Auth."""
    url = f"{fixture_server.base_url}/admin/secret"
    health = check_target_health(url)
    assert health.accessible is False
    assert health.is_protected is True
    assert health.protection_type == "http_auth"


def test_fixture_live_vercel_challenge_detected(fixture_server, monkeypatch):
    """Memverifikasi proteksi Vercel Challenge terdeteksi dan scan ditandai blocked."""
    monkeypatch.setattr(settings, "vercel_protection_bypass_secret", "")
    monkeypatch.setattr(settings, "vercel_bypass_secret", "")
    url = f"{fixture_server.base_url}/vercel-demo"
    health = check_target_health(url)
    assert health.accessible is False
    assert health.is_protected is True
    assert health.protection_type == "vercel_challenge"


def test_fixture_live_vercel_bypass_success(fixture_server, monkeypatch):
    """Memverifikasi bahwa secret bypass yang valid berhasil membuka proteksi Vercel."""
    monkeypatch.setattr(settings, "vercel_protection_bypass_secret", "valid-vercel-secret-key")
    monkeypatch.setattr(settings, "vercel_bypass_secret", "valid-vercel-secret-key")
    url = f"{fixture_server.base_url}/vercel-demo"
    health = check_target_health(url)
    assert health.accessible is True
    assert health.status_code == 200
    assert health.is_protected is False


def test_fixture_live_redirect_out_of_scope_detected(fixture_server):
    """Memverifikasi bahwa redirect ke domain eksternal terdeteksi dan diblokir."""
    url = f"{fixture_server.base_url}/external-redirect"
    health = check_target_health(url)
    assert health.accessible is False
    assert health.is_redirected is True
    assert health.redirect_in_scope is False
    assert health.protection_type == "redirect_out_of_scope"


def test_destructive_endpoints_never_touched(fixture_server):
    """
    Membuktikan bahwa endpoint kontrol destruktif (/delete-account)
    tidak pernah dipanggil selama proses scanning karena terdaftar di DEFAULT_EXCLUDES.
    """
    FixtureState.reset()
    assert FixtureState.destructive_called is False

    mock_zap = MagicMock()
    mock_zap.spider.scan.return_value = "1"
    mock_zap.spider.status.return_value = 100
    mock_zap.spider.results.return_value = [
        f"{fixture_server.base_url}/",
        f"{fixture_server.base_url}/about",
        f"{fixture_server.base_url}/api/public",
    ]
    mock_zap.pscan.records_to_scan = 0
    mock_zap.core.alerts.return_value = [
        {
            "pluginId": "10020",
            "alert": "Anti-clickjacking Header Missing",
            "risk": "Medium",
            "confidence": "Medium",
            "url": f"{fixture_server.base_url}/about",
            "description": "The response does not protect against clickjacking.",
        }
    ]

    with patch("app.zap_client.check_zap_connectivity", return_value=True), \
         patch("app.zap_client._zap", return_value=mock_zap):

        res = execute_scan(fixture_server.base_url, scan_mode="passive")

        # Pastikan excludes didaftarkan ke ZAP
        exclude_calls = [c[0][1] for c in mock_zap.context.exclude_from_context.call_args_list]
        assert any("delete" in pat for pat in exclude_calls)
        assert any("reset-db" in pat for pat in exclude_calls)

        # Bukti konkrit: endpoint destruktif pada server fixture tidak pernah diakses
        assert FixtureState.destructive_called is False
        assert len(FixtureState.destructive_hits) == 0

        # Bukti coverage
        assert res.verdict_status == "completed"
        assert res.coverage.total_urls_discovered >= 3
        assert len(res.technical_alerts) == 1
        assert res.technical_alerts[0].name == "Anti-clickjacking Header Missing"


@pytest.mark.skipif(not check_zap_connectivity(), reason="OWASP ZAP daemon tidak aktif di localhost:8090")
def test_real_zap_passive_scan_integration(fixture_server):
    """
    Priority 4: Uji integrasi nyata terhadap daemon OWASP ZAP (jika aktif):
    - Fixture dapat diakses oleh ZAP
    - Spider menemukan route crawlable
    - Passive scanner menghasilkan alert header (misal Anti-clickjacking / CSP)
    - Active scan tidak dijalankan pada mode passive
    - Endpoint destruktif (/delete-account) tidak pernah dipanggil
    - Redirect out of scope tidak diikuti
    """
    FixtureState.reset()
    res = execute_scan(fixture_server.base_url, scan_mode="passive")

    # Fixture dapat diakses oleh ZAP
    assert res.target_accessible is True
    assert res.verdict_status == "completed"

    # Spider menemukan route
    assert res.coverage.total_urls_discovered > 1
    assert any("/about" in u for u in res.coverage.urls_discovered)
    assert any("/api/public" in u for u in res.coverage.urls_discovered)

    # Active scanner tidak dijalankan
    assert res.coverage.active_scan_status == "skipped"

    # Destructive endpoints never called
    assert FixtureState.destructive_called is False
    assert len(FixtureState.destructive_hits) == 0

    # Passive scanner memproses alert
    assert len(res.technical_alerts) > 0


@pytest.mark.skipif(not check_zap_connectivity(), reason="OWASP ZAP daemon tidak aktif di localhost:8090")
def test_real_zap_active_scan_completes(fixture_server):
    """
    Priority 4: Uji integrasi nyata mode active terhadap daemon OWASP ZAP:
    - Active scanner menyelesaikan proses pemindaian
    - Coverage merekam active scan completed
    - Endpoint destruktif tetap terlindungi dan tidak disentuh
    """
    FixtureState.reset()
    res = execute_scan(fixture_server.base_url, scan_mode="active")

    assert res.target_accessible is True
    assert res.coverage.active_scan_status == "completed"
    assert FixtureState.destructive_called is False

