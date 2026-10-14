from app.sanitizer import _clean, prepare_alerts


def test_clean_jwt():
    raw = "Header Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThis"
    cleaned = _clean(raw, 200)
    assert "[JWT]" in cleaned
    assert "eyJhbGci" not in cleaned


def test_clean_secrets():
    samples = [
        ("Bearer abcdef123456", "Bearer [REDACTED]"),
        ("api_key=secretapikey123", "api_key=[REDACTED]"),
        ("password: supersecretpass", "password: [REDACTED]"),
        ("token: 'myauthtoken999'", "token: '[REDACTED]'"),
        ("x-vercel-protection-bypass: mybypasssecret123", "x-vercel-protection-bypass: [REDACTED]"),
    ]
    for raw, expected in samples:
        cleaned = _clean(raw, 200)
        assert "[REDACTED]" in cleaned


def test_clean_emails():
    raw = "User email is admin@company.com"
    cleaned = _clean(raw, 200)
    assert "[EMAIL]" in cleaned
    assert "admin@company.com" not in cleaned


def test_clean_truncation():
    raw = "A" * 500
    cleaned = _clean(raw, 50)
    assert len(cleaned) == 50


def test_clean_none_and_empty():
    assert _clean(None, 50) == ""
    assert _clean("", 50) == ""


def test_prepare_alerts_deduplication():
    raw_alerts = [
        {
            "pluginId": "10020",
            "method": "GET",
            "param": "id",
            "url": "http://localhost:8000/api/users?id=1",
            "risk": "High",
            "alert": "SQL Injection",
        },
        {
            "pluginId": "10020",
            "method": "GET",
            "param": "id",
            "url": "http://localhost:8000/api/users?id=2",
            "risk": "High",
            "alert": "SQL Injection",
        },
    ]
    prepared = prepare_alerts(raw_alerts)
    assert len(prepared) == 1
    assert prepared[0]["alert_id"] == "A001"


def test_prepare_alerts_risk_sorting():
    raw_alerts = [
        {"pluginId": "1", "method": "GET", "param": "a", "url": "http://localhost/1", "risk": "Low"},
        {"pluginId": "2", "method": "GET", "param": "b", "url": "http://localhost/2", "risk": "High"},
        {"pluginId": "3", "method": "GET", "param": "c", "url": "http://localhost/3", "risk": "Informational"},
        {"pluginId": "4", "method": "GET", "param": "d", "url": "http://localhost/4", "risk": "Medium"},
    ]
    prepared = prepare_alerts(raw_alerts)
    risks = [a["risk"] for a in prepared]
    assert risks == ["High", "Medium", "Low", "Informational"]
    assert [a["alert_id"] for a in prepared] == ["A001", "A002", "A003", "A004"]


def test_prepare_alerts_max_alerts_limit():
    raw_alerts = [
        {
            "pluginId": str(i),
            "method": "GET",
            "param": f"p_{i}",
            "url": f"http://localhost/{i}",
            "risk": "Low",
        }
        for i in range(100)
    ]
    prepared = prepare_alerts(raw_alerts)
    assert len(prepared) == 50
    assert prepared[-1]["alert_id"] == "A050"


def test_prepare_alerts_sanitizes_content():
    raw_alerts = [
        {
            "pluginId": "101",
            "method": "POST",
            "param": "token",
            "url": "http://localhost/login?token=mysecrettoken123",
            "attack": "bearer secrettoken123456",
            "evidence": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.secret_sig",
            "description": "User user@test.com leak",
            "risk": "Medium",
        }
    ]
    prepared = prepare_alerts(raw_alerts)
    assert len(prepared) == 1
    item = prepared[0]
    assert "[REDACTED]" in item["url"]
    assert "[REDACTED]" in item["attack"]
    assert "[JWT]" in item["evidence"]
    assert "[EMAIL]" in item["zap_description"]
