from fastapi.testclient import TestClient

from app.config import settings
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "default_scan_mode" in data
    assert data["default_scan_mode"] == "passive"


def test_api_auth_required(monkeypatch):
    monkeypatch.setattr(settings, "api_auth_token", "super-secret-token")

    # Tanpa header Authorization -> 401
    resp = client.post("/scans", json={"target_url": "http://localhost:8000"})
    assert resp.status_code == 401
    assert "Akses tidak diotorisasi" in resp.json()["detail"]

    # Token salah -> 401
    resp = client.post(
        "/scans",
        json={"target_url": "http://localhost:8000"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401

    # Token benar -> 202 (atau 403 guardrail jika host belum diizinkan)
    monkeypatch.setattr(settings, "allowed_hosts", ["localhost"])
    resp = client.post(
        "/scans",
        json={"target_url": "http://localhost:8000"},
        headers={"Authorization": "Bearer super-secret-token"},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert "scan_id" in data
    assert len(data["scan_id"]) == 32  # 16 bytes hex token
    assert data["state"] == "queued"


def test_get_scan_not_found(monkeypatch):
    monkeypatch.setattr(settings, "api_auth_token", "")
    resp = client.get("/scans/nonexistent_scan_id_123")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "scan tidak ditemukan"


def test_guardrail_rejection_at_api_level(monkeypatch):
    monkeypatch.setattr(settings, "api_auth_token", "")
    monkeypatch.setattr(settings, "allowed_hosts", ["staging.internal"])

    resp = client.post("/scans", json={"target_url": "http://evil-domain.com"})
    assert resp.status_code == 403
    assert "tidak ada di allowlist" in resp.json()["detail"]
