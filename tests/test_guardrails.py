import socket
from unittest.mock import patch

import pytest

from app.config import settings
from app.guardrails import TargetNotAllowed, assert_target_allowed


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


def test_host_not_in_allowed_hosts(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["localhost", "127.0.0.1"])
    with pytest.raises(TargetNotAllowed, match="Host 'evil.com' tidak ada di allowlist"):
        assert_target_allowed("http://evil.com")


def test_allowed_host_localhost_success(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["localhost", "127.0.0.1"])
    monkeypatch.setattr(settings, "require_private_ip", True)

    # Should not raise exception
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


def test_unresolvable_host_rejected(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["unresolvable.internal"])
    monkeypatch.setattr(settings, "require_private_ip", True)

    with patch("socket.getaddrinfo", side_effect=socket.gaierror("getaddrinfo failed")):
        with pytest.raises(TargetNotAllowed, match="Gagal me-resolve host"):
            assert_target_allowed("http://unresolvable.internal")
