import socket
from unittest.mock import MagicMock, patch

import pytest

from app.config import settings
from app.guardrails import TargetNotAllowed, assert_target_allowed, is_host_allowed
from app.sanitizer import _clean
from app.zap_client import run_scan


# =====================================================================
# 1. TEST VERCEL BYPASS SECRET & SECRET STORAGE / LEAKAGE TO LLM
# =====================================================================

def test_literal_secret_redacted_without_prefix(monkeypatch):
    """Pastikan secret literal disensor meskipun tidak diawali kata kunci seperti 'secret:'."""
    secret_token = "my-super-secret-bypass-token-xyz123"
    monkeypatch.setattr(settings, "vercel_bypass_secret", secret_token)

    raw_text = f"An error occurred while evaluating token {secret_token} on the server."
    cleaned = _clean(raw_text, limit=500)

    assert secret_token not in cleaned
    assert "[REDACTED_SECRET]" in cleaned


def test_zap_and_llm_api_keys_literally_redacted(monkeypatch):
    """Pastikan ZAP API key dan LLM API key tidak bocor ke output sanitizer."""
    monkeypatch.setattr(settings, "zap_api_key", "secret-zap-key-998877")
    monkeypatch.setattr(settings, "llm_api_key", "sk-ant-test-super-secret-key")

    raw_text = "Dump: zap_key=secret-zap-key-998877, anthropic=sk-ant-test-super-secret-key"
    cleaned = _clean(raw_text, limit=500)

    assert "secret-zap-key-998877" not in cleaned
    assert "sk-ant-test-super-secret-key" not in cleaned


# =====================================================================
# 2. TEST ALLOWLIST WILDCARD & HOSTNAME OUT-OF-SCOPE
# =====================================================================

def test_dangerous_tld_wildcards_rejected():
    """Wildcard yang terlalu luas (*.com, *.app, *) harus ditolak oleh guardrail."""
    assert is_host_allowed("google.com", ["*.com"]) is False
    assert is_host_allowed("myapp.app", ["*.app"]) is False
    assert is_host_allowed("evil.io", ["*.*"]) is False
    assert is_host_allowed("evil.com", ["*"]) is False


def test_specific_subdomain_wildcard_allowed_and_isolated():
    """Wildcard subdomain spesifik (design-log-*.vercel.app) hanya mengizinkan host dalam scope."""
    allowed = ["design-log-*.vercel.app"]

    # In scope
    assert is_host_allowed("design-log-preview-1.vercel.app", allowed) is True
    assert is_host_allowed("design-log-git-feature.vercel.app", allowed) is True

    # Out of scope: domain berbeda atau prefix berbeda
    assert is_host_allowed("other-project.vercel.app", allowed) is False
    assert is_host_allowed("design-log-preview.evil.com", allowed) is False
    assert is_host_allowed("evil-design-log.vercel.app", allowed) is False


# =====================================================================
# 3. TEST SSRF, CLOUD METADATA, & DNS REBINDING PROTECTION
# =====================================================================

def test_cloud_metadata_ip_blocked(monkeypatch):
    """Host yang me-resolve ke IP Cloud Metadata (169.254.169.254) harus selalu diblokir."""
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["staging.internal"])
    monkeypatch.setattr(settings, "require_private_ip", True)

    mock_addr = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]
    with patch("socket.getaddrinfo", return_value=mock_addr):
        with pytest.raises(TargetNotAllowed, match="cloud metadata"):
            assert_target_allowed("http://staging.internal")


def test_dns_rebinding_external_host_resolving_to_loopback_blocked(monkeypatch):
    """Domain publik eksternal yang tiba-tiba me-resolve ke 127.0.0.1 (DNS Rebinding) harus diblokir."""
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["design-log-ruby.vercel.app"])
    monkeypatch.setattr(settings, "require_private_ip", False)

    mock_addr = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
    with patch("socket.getaddrinfo", return_value=mock_addr):
        with pytest.raises(TargetNotAllowed, match="Potensi DNS Rebinding/SSRF"):
            assert_target_allowed("https://design-log-ruby.vercel.app")


def test_valid_public_ip_for_vercel_allowed(monkeypatch):
    """Domain Vercel dengan IP publik sah (Anycast) harus diizinkan bila REQUIRE_PRIVATE_IP=False."""
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["design-log-ruby.vercel.app"])
    monkeypatch.setattr(settings, "require_private_ip", False)

    mock_addr = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("76.76.21.21", 443))]
    with patch("socket.getaddrinfo", return_value=mock_addr):
        assert_target_allowed("https://design-log-ruby.vercel.app")


# =====================================================================
# 4. TEST SPIDER POST_FORM DISABLEMENT & PASSIVE SCAN MODE ISOLATION
# =====================================================================

def test_passive_mode_sets_safe_mode_and_skips_ascan():
    """Mode passive harus mengunci engine ZAP ke 'safe', mematikan post_form spider, dan tidak memanggil ascan.scan."""
    mock_zap = MagicMock()
    mock_zap.spider.status.return_value = "100"
    mock_zap.pscan.records_to_scan = "0"
    mock_zap.core.alerts.return_value = []

    with patch("app.zap_client._zap", return_value=mock_zap):
        alerts = run_scan(
            target="https://design-log-ruby.vercel.app",
            scan_mode="passive",
            custom_headers={"x-vercel-protection-bypass": "secret-token-123"},
        )

        assert alerts == []
        # 1. Engine mode ZAP wajib diset ke 'protect' (hanya izinkan interaksi dengan target in-scope)
        mock_zap.core.set_mode.assert_called_with("protect")

        # 2. Spider post_form wajib dinonaktifkan (read-only, tidak submit POST)
        mock_zap.spider.set_option_post_form.assert_called_with(False)

        # 3. Active scan TIDAK BOLEH dipanggil sama sekali
        mock_zap.ascan.scan.assert_not_called()


def test_active_mode_sets_protect_mode_and_calls_ascan():
    """Mode active harus mengatur mode ke 'protect' dan memanggil ascan.scan."""
    mock_zap = MagicMock()
    mock_zap.spider.status.return_value = "100"
    mock_zap.pscan.records_to_scan = "0"
    mock_zap.ascan.status.return_value = "100"
    mock_zap.core.alerts.return_value = []

    with patch("app.zap_client._zap", return_value=mock_zap):
        run_scan(
            target="https://design-log-ruby.vercel.app",
            scan_mode="active",
        )

        mock_zap.core.set_mode.assert_called_with("protect")
        mock_zap.ascan.scan.assert_called_once()


# =====================================================================
# 5. TEST ZAP REPLACER HEADER URL ISOLATION (NO LEAK TO 3RD PARTY)
# =====================================================================

def test_zap_replacer_restricts_headers_to_target_url():
    """Pastikan ZAP Replacer membatasi parameter 'url' sehingga bypass secret tidak bocor ke CDN/origin lain."""
    mock_zap = MagicMock()
    mock_zap.spider.status.return_value = "100"
    mock_zap.pscan.records_to_scan = "0"
    mock_zap.core.alerts.return_value = []
    mock_zap.replacer.rules = []

    target = "https://design-log-ruby.vercel.app"
    with patch("app.zap_client._zap", return_value=mock_zap):
        run_scan(
            target=target,
            scan_mode="passive",
            custom_headers={"x-vercel-protection-bypass": "secret-token-123"},
        )

        # Cek pemanggilan replacer.add_rule
        mock_zap.replacer.add_rule.assert_called()
        call_kwargs = mock_zap.replacer.add_rule.call_args.kwargs

        # Parameter 'url' wajib berupa regex target agar hanya cocok dengan URL target dan tidak bocor ke origin lain (misal CDN / third-party)
        assert "url" in call_kwargs
        url_pattern = call_kwargs["url"]
        import re
        assert re.match(url_pattern, target + "/api/tasks") is not None
        assert re.match(url_pattern, "https://fonts.googleapis.com/css") is None
        assert re.match(url_pattern, "https://evil.com/leak") is None
        assert call_kwargs["matchstring"] == "x-vercel-protection-bypass"
        assert call_kwargs["replacement"] == "secret-token-123"
