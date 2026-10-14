import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.llm_client import analyze
from app.main import SCANS, app

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_scans():
    SCANS.clear()
    yield
    SCANS.clear()


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "environment" in data
    assert "zap_url" in data
    assert "llm_configured" in data


def test_list_scans_empty():
    response = client.get("/scans")
    assert response.status_code == 200
    assert response.json() == []


def test_get_scan_not_found():
    response = client.get("/scans/notfound123")
    assert response.status_code == 404
    assert response.json()["detail"] == "scan tidak ditemukan"


def test_create_scan_forbidden_target(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["localhost", "127.0.0.1"])

    response = client.post("/scans", json={"target_url": "http://evil.com/app"})
    assert response.status_code == 403
    assert "Host 'evil.com' tidak ada di allowlist" in response.json()["detail"]


def test_create_scan_allowed_target(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["localhost", "127.0.0.1"])
    monkeypatch.setattr(settings, "require_private_ip", True)

    # Disable background task actual execution in test
    monkeypatch.setattr("app.main.pipeline", lambda scan_id, req: None)

    response = client.post(
        "/scans",
        json={"target_url": "http://127.0.0.1:8000", "framework": "fastapi"},
    )
    assert response.status_code == 202
    data = response.json()
    assert "scan_id" in data
    assert data["state"] == "queued"

    # Verify retrieval
    scan_id = data["scan_id"]
    get_resp = client.get(f"/scans/{scan_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["scan_id"] == scan_id


def test_fallback_triage_when_no_llm_key(monkeypatch):
    monkeypatch.setattr(settings, "llm_api_key", "")
    sample_alerts = [
        {
            "alert_id": "A001",
            "name": "Cross-Site Scripting (XSS)",
            "risk": "High",
            "url": "http://127.0.0.1:8000/search?q=test",
            "param": "q",
            "evidence": "<script>alert(1)</script>",
            "cwe": "79",
        },
        {
            "alert_id": "A002",
            "name": "Missing Anti-clickjacking Header",
            "risk": "Low",
            "url": "http://127.0.0.1:8000/",
            "param": "",
            "evidence": "",
            "cwe": "1021",
        },
    ]

    findings = analyze(sample_alerts, framework="fastapi")
    assert len(findings) == 2
    assert findings[0].alert_id == "A001"
    assert findings[0].severity == "high"
    assert findings[0].verdict == "needs_manual_verification"
    assert "fallback" in findings[0].reasoning.lower()
    assert findings[1].severity == "low"


def test_analyze_empty_alerts():
    findings = analyze([], framework="fastapi")
    assert findings == []


def test_create_scan_with_passive_mode_and_headers(monkeypatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "allowed_hosts", ["design-log-ruby.vercel.app"])
    monkeypatch.setattr(settings, "require_private_ip", False)

    recorded_req = []
    monkeypatch.setattr("app.main.pipeline", lambda scan_id, req: recorded_req.append(req))

    response = client.post(
        "/scans",
        json={
            "target_url": "https://design-log-ruby.vercel.app",
            "framework": "react-vite",
            "scan_mode": "passive",
            "custom_headers": {"x-vercel-protection-bypass": "test-secret-123"},
        },
    )
    assert response.status_code == 202
    assert len(recorded_req) == 1
    assert recorded_req[0].scan_mode == "passive"
    assert recorded_req[0].custom_headers["x-vercel-protection-bypass"] == "test-secret-123"

