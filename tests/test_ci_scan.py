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


def test_main_terminal_state_blocked():
    """Memverifikasi bahwa state 'blocked' segera menghentikan polling dan mengembalikan exit code 2."""
    from scripts.ci_scan import main

    with patch("scripts.ci_scan.wait_for_orchestrator", return_value=True), \
         patch("scripts.ci_scan.http_post", return_value={"scan_id": "blk123"}), \
         patch("scripts.ci_scan.http_get", return_value={
             "scan_id": "blk123",
             "state": "blocked",
             "report": {
                 "verdict_status": "blocked",
                 "target_health": {"diagnostic_message": "Vercel Challenge 401"},
                 "limitations": ["Scan diblokir oleh proteksi target"],
             }
         }):

        code = main(["--target-url", "http://localhost:8000", "--poll-interval", "0"])
        assert code == 2


def test_main_terminal_state_inconclusive():
    """Memverifikasi bahwa state 'inconclusive' segera menghentikan polling dan mengembalikan exit code 2."""
    from scripts.ci_scan import main

    with patch("scripts.ci_scan.wait_for_orchestrator", return_value=True), \
         patch("scripts.ci_scan.http_post", return_value={"scan_id": "inc123"}), \
         patch("scripts.ci_scan.http_get", return_value={
             "scan_id": "inc123",
             "state": "inconclusive",
             "report": {
                 "verdict_status": "inconclusive",
                 "limitations": ["Discovery hanya menemukan root URL"],
             }
         }):

        code = main(["--target-url", "http://localhost:8000", "--poll-interval", "0"])
        assert code == 2


def test_main_terminal_state_failed():
    """Memverifikasi bahwa state 'failed' (kegagalan pipeline) mengembalikan exit code 3."""
    from scripts.ci_scan import main

    with patch("scripts.ci_scan.wait_for_orchestrator", return_value=True), \
         patch("scripts.ci_scan.http_post", return_value={"scan_id": "fail123"}), \
         patch("scripts.ci_scan.http_get", return_value={
             "scan_id": "fail123",
             "state": "failed",
             "error": "ZAP daemon crash",
         }):

        code = main(["--target-url", "http://localhost:8000", "--poll-interval", "0"])
        assert code == 3


def test_main_terminal_state_timeout():
    """Memverifikasi bahwa pemindaian yang melebihi batas waktu mengembalikan exit code 3."""
    from scripts.ci_scan import main

    with patch("scripts.ci_scan.wait_for_orchestrator", return_value=True), \
         patch("scripts.ci_scan.http_post", return_value={"scan_id": "to123"}), \
         patch("scripts.ci_scan.http_get", return_value={"state": "active_scanning"}), \
         patch("time.sleep", return_value=None):

        code = main(["--target-url", "http://localhost:8000", "--timeout", "1", "--poll-interval", "2"])
        assert code == 3


def test_main_terminal_state_done_with_vulnerability():
    """Memverifikasi bahwa temuan True Positive High menghasilkan exit code 1."""
    from scripts.ci_scan import main

    with patch("scripts.ci_scan.wait_for_orchestrator", return_value=True), \
         patch("scripts.ci_scan.http_post", return_value={"scan_id": "done123"}), \
         patch("scripts.ci_scan.http_get", return_value={
             "scan_id": "done123",
             "state": "done",
             "report": {
                 "findings": [
                     {"verdict": "true_positive", "severity": "high", "title": "SQL Injection"}
                 ]
             }
         }):

        code = main(["--target-url", "http://localhost:8000", "--fail-on", "high"])
        assert code == 1


def test_main_terminal_state_done_clean():
    """Memverifikasi bahwa scan selesai tanpa kerentanan menghasilkan exit code 0."""
    from scripts.ci_scan import main

    with patch("scripts.ci_scan.wait_for_orchestrator", return_value=True), \
         patch("scripts.ci_scan.http_post", return_value={"scan_id": "clean123"}), \
         patch("scripts.ci_scan.http_get", return_value={
             "scan_id": "clean123",
             "state": "done",
             "report": {
                 "findings": []
             }
         }):

        code = main(["--target-url", "http://localhost:8000", "--fail-on", "high"])
        assert code == 0


def test_main_terminal_state_unknown():
    """Memverifikasi bahwa state yang tidak dikenal mengembalikan exit code 3 dan tidak dianggap sukses."""
    from scripts.ci_scan import main

    with patch("scripts.ci_scan.wait_for_orchestrator", return_value=True), \
         patch("scripts.ci_scan.http_post", return_value={"scan_id": "unk123"}), \
         patch("scripts.ci_scan.http_get", return_value={
             "scan_id": "unk123",
             "state": "unexpected_corrupt_state",
         }):

        code = main(["--target-url", "http://localhost:8000", "--timeout", "1", "--poll-interval", "2"])
        assert code == 3


def test_main_orchestrator_unreachable():
    """Memverifikasi bahwa kegagalan menghubungi orchestrator mengembalikan exit code 3."""
    from scripts.ci_scan import main

    with patch("scripts.ci_scan.wait_for_orchestrator", return_value=False):
        code = main(["--target-url", "http://localhost:8000"])
        assert code == 3


def test_main_init_post_failure():
    """Memverifikasi bahwa kegagalan inisiasi request scan mengembalikan exit code 3."""
    from scripts.ci_scan import main

    with patch("scripts.ci_scan.wait_for_orchestrator", return_value=True), \
         patch("scripts.ci_scan.http_post", side_effect=OSError("Network unreachable")):
        code = main(["--target-url", "http://localhost:8000"])
        assert code == 3


def test_main_terminal_state_empty_or_none():
    """Memverifikasi bahwa respons dengan state kosong atau None mengembalikan exit code 3."""
    from scripts.ci_scan import main

    with patch("scripts.ci_scan.wait_for_orchestrator", return_value=True), \
         patch("scripts.ci_scan.http_post", return_value={"scan_id": "emp123"}), \
         patch("scripts.ci_scan.http_get", return_value={"scan_id": "emp123", "state": None}):
        code = main(["--target-url", "http://localhost:8000", "--poll-interval", "0"])
        assert code == 3


def test_main_invalid_api_response():
    """Memverifikasi bahwa respons API yang bukan format dict mengembalikan exit code 3."""
    from scripts.ci_scan import main

    with patch("scripts.ci_scan.wait_for_orchestrator", return_value=True), \
         patch("scripts.ci_scan.http_post", return_value={"scan_id": "inv123"}), \
         patch("scripts.ci_scan.http_get", return_value="Invalid non-json HTML response"):
        code = main(["--target-url", "http://localhost:8000", "--poll-interval", "0"])
        assert code == 3


def test_main_polling_repeated_failures():
    """Memverifikasi bahwa kegagalan polling berturut-turut menghentikan loop dan keluar dengan exit code 3."""
    from scripts.ci_scan import main

    with patch("scripts.ci_scan.wait_for_orchestrator", return_value=True), \
         patch("scripts.ci_scan.http_post", return_value={"scan_id": "pollfail123"}), \
         patch("scripts.ci_scan.http_get", side_effect=OSError("Connection reset by peer")), \
         patch("time.sleep", return_value=None):
        code = main(["--target-url", "http://localhost:8000", "--timeout", "100", "--poll-interval", "0"])
        assert code == 3
