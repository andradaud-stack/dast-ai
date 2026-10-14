import socket
from unittest.mock import patch

import pytest

from app.config import settings
from app.guardrails import (
    TargetNotAllowed,
    assert_target_allowed,
    build_zap_scope_regex,
    is_url_in_scope,
)


def test_environment_not_allowed(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    with pytest.raises(TargetNotAllowed, match="ENVIRONMENT harus 'local' atau 'staging'"):
        assert_target_allowed("http://localhost:8000")


def test_invalid_url_scheme(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    with pytest.raises(TargetNotAllowed, match="URL tidak valid"):
        assert_target_allowed("ftp://localhost:8000")

    with pytest.raises(TargetNotAllowed, match="URL tidak valid"):
        assert_target_allowed("not-a-valid-url")


def test_invalid_url_missing_hostname(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    with pytest.raises(TargetNotAllowed, match="URL tidak valid"):
        assert_target_allowed("http://")


def test_userinfo_rejected(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["localhost"])
    with pytest.raises(TargetNotAllowed, match="URL mengandung userinfo"):
        assert_target_allowed("http://admin:secret@localhost:8000")


def test_invalid_port_rejected(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["localhost"])
    with pytest.raises(TargetNotAllowed, match="Port URL di luar rentang valid"):
        assert_target_allowed("http://localhost:999999")


def test_host_not_in_allowed_hosts(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["localhost", "127.0.0.1"])
    with pytest.raises(TargetNotAllowed, match="Host 'evil.com' tidak ada di allowlist"):
        assert_target_allowed("http://evil.com")


def test_allowed_host_localhost_success(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["localhost", "127.0.0.1"])
    monkeypatch.setattr(settings, "require_private_ip", True)

    assert_target_allowed("http://localhost:8000")
    assert_target_allowed("http://127.0.0.1:8000/api")


def test_public_ip_rejected(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["staging.example.com"])
    monkeypatch.setattr(settings, "require_private_ip", True)

    mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        with pytest.raises(TargetNotAllowed, match="resolve ke IP publik"):
            assert_target_allowed("http://staging.example.com")


def test_private_ip_allowed(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["staging.internal"])
    monkeypatch.setattr(settings, "require_private_ip", True)

    mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 80))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        assert_target_allowed("http://staging.internal")


def test_cloud_metadata_ip_rejected(monkeypatch):
    """Memastikan alamat cloud metadata AWS/GCP/Azure 169.254.169.254 selalu diblokir."""
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["metadata.internal"])
    monkeypatch.setattr(settings, "require_private_ip", False)

    mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        with pytest.raises(TargetNotAllowed, match="cloud metadata"):
            assert_target_allowed("http://metadata.internal")


def test_multicast_ip_rejected(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["multicast.internal"])
    monkeypatch.setattr(settings, "require_private_ip", False)

    mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("224.0.0.1", 80))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        with pytest.raises(TargetNotAllowed, match="cloud metadata|multicast"):
            assert_target_allowed("http://multicast.internal")


def test_vercel_wildcard_domain_matching(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["*.dast-test.vercel.app"])
    monkeypatch.setattr(settings, "require_private_ip", False)

    mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("76.76.21.21", 80))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        # Subdomain valid 1 tingkat diizinkan
        assert_target_allowed("https://preview-123.dast-test.vercel.app")
        assert_target_allowed("https://staging.dast-test.vercel.app")

        # Domain serupa atau subdomain ganda harus DITOLAK
        with pytest.raises(TargetNotAllowed, match="tidak ada di allowlist"):
            assert_target_allowed("https://evil-dast-test.vercel.app")

        with pytest.raises(TargetNotAllowed, match="tidak ada di allowlist"):
            assert_target_allowed("https://sub.extra.dast-test.vercel.app")

        with pytest.raises(TargetNotAllowed, match="tidak ada di allowlist"):
            assert_target_allowed("https://otherdomain.vercel.app")


def test_build_zap_scope_regex():
    import re
    # 1. HTTP dengan port eksplisit
    regex_str = build_zap_scope_regex("http://localhost:8000")
    pattern = re.compile(regex_str)

    assert pattern.match("http://localhost:8000")
    assert pattern.match("http://localhost:8000/api/users")
    assert pattern.match("http://localhost:8000/login?redirect=1")

    # Mencegah URL spoofing & port mismatch
    assert not pattern.match("http://localhost:8000.evil.com")
    assert not pattern.match("http://otherhost:8000")
    assert not pattern.match("https://localhost:8000")
    assert not pattern.match("http://localhost:9000/api")

    # 2. HTTPS tanpa port eksplisit (Priority 1 Point 3)
    target_vercel = "https://example.vercel.app"
    v_regex = re.compile(build_zap_scope_regex(target_vercel))

    # In scope
    assert v_regex.match("https://example.vercel.app")
    assert v_regex.match("https://example.vercel.app/api/tasks")
    assert v_regex.match("https://example.vercel.app:443/login")

    # Wajib DITOLAK: attacker subdomain, prefix spoofing, port unauthorized
    assert not v_regex.match("https://example.vercel.app.attacker.test")
    assert not v_regex.match("https://attacker.test/example.vercel.app")
    assert not v_regex.match("https://example.vercel.app:8443")
    assert not v_regex.match("http://example.vercel.app")


def test_is_url_in_scope():
    orig = "http://localhost:8000/app"
    assert is_url_in_scope("http://localhost:8000/dashboard", orig)
    assert is_url_in_scope("http://localhost:8000/api/data", orig)

    # Out of scope
    assert not is_url_in_scope("http://attacker.com/evil", orig)
    assert not is_url_in_scope("http://localhost:9000/app", orig)
    assert not is_url_in_scope("https://localhost:8000/app", orig)
    assert not is_url_in_scope("javascript:alert(1)", orig)

    # Priority 1 tests via is_url_in_scope
    target = "https://example.vercel.app"
    assert is_url_in_scope("https://example.vercel.app/home", target)
    assert not is_url_in_scope("https://example.vercel.app.attacker.test", target)
    assert not is_url_in_scope("https://attacker.test/example.vercel.app", target)
    assert not is_url_in_scope("https://example.vercel.app:8443", target)
