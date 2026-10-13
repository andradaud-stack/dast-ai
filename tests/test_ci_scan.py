import json
from unittest.mock import patch
import pytest

from scripts.ci_scan import (
    build_markdown_report,
    evaluate_findings,
    wait_for_orchestrator,
)


def test_evaluate_findings_no_vulnerabilities():
    findings = [
        {"verdict": "likely_false_positive", "severity": "high", "title": "SQLi FP"},
        {"verdict": "needs_manual_verification", "severity": "medium", "title": "XSS Review"},
    ]
    failed, reason = evaluate_findings(findings, fail_on="high")
    assert failed is False
    assert reason == ""


def test_evaluate_findings_critical_true_positive():
    findings = [
        {"verdict": "true_positive", "severity": "critical", "title": "RCE in Endpoint"},
    ]
    failed, reason = evaluate_findings(findings, fail_on="high")
    assert failed is True
    assert "Ditemukan 1 kerentanan terkonfirmasi" in reason
    assert "RCE in Endpoint" in reason


def test_evaluate_findings_medium_with_high_threshold():
    findings = [
        {"verdict": "true_positive", "severity": "medium", "title": "Missing CSRF"},
    ]
    # Threshold is high, medium should not trigger failure
    failed, reason = evaluate_findings(findings, fail_on="high")
    assert failed is False

    # But should fail if threshold is medium
    failed_med, reason_med = evaluate_findings(findings, fail_on="medium")
    assert failed_med is True
    assert "Missing CSRF" in reason_med


def test_evaluate_findings_fail_on_none():
    findings = [
        {"verdict": "true_positive", "severity": "critical", "title": "SQL Injection"},
    ]
    failed, reason = evaluate_findings(findings, fail_on="none")
    assert failed is False


def test_evaluate_findings_fail_on_any():
    findings = [
        {"verdict": "true_positive", "severity": "low", "title": "Information Disclosure"},
    ]
    failed, reason = evaluate_findings(findings, fail_on="any")
    assert failed is True


def test_build_markdown_report():
    scan_data = {
        "scan_id": "test1234",
        "state": "done",
        "report": {
            "total_alerts": 5,
            "true_positive": 1,
            "false_positive": 3,
            "needs_review": 1,
            "findings": [
                {
                    "alert_id": "A001",
                    "title": "SQL Injection",
                    "severity": "high",
                    "verdict": "true_positive",
                    "confidence": 0.95,
                    "cwe": "89",
                    "reasoning": "Error message in SQL syntax observed.",
                    "evidence_quote": "syntax error near SELECT",
                    "fix": {
                        "summary": "Use prepared statements",
                        "language": "python",
                        "code_patch": "db.execute('SELECT * FROM users WHERE id = %s', (uid,))",
                        "caveats": "Ensure database driver supports parameterized queries",
                    },
                    "verification_steps": ["Test with single quote in query parameter"],
                }
            ],
        },
    }

    md = build_markdown_report("http://localhost:8000", scan_data, failed=True, fail_reason="High vuln detected")
    assert "# 🛡️ DAST-AI Security Scan Report" in md
    assert "test1234" in md
    assert "SQL Injection" in md
    assert "CWE-89" in md
    assert "Use prepared statements" in md
    assert "db.execute" in md


def test_wait_for_orchestrator_success():
    with patch("scripts.ci_scan.http_get", return_value={"status": "ok", "environment": "staging"}):
        ready = wait_for_orchestrator("http://127.0.0.1:8000", max_wait_seconds=5)
        assert ready is True


def test_wait_for_orchestrator_failure():
    with patch("scripts.ci_scan.http_get", side_effect=OSError("Connection refused")):
        ready = wait_for_orchestrator("http://127.0.0.1:8000", max_wait_seconds=2)
        assert ready is False
