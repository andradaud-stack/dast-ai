#!/usr/bin/env python3
"""DAST-AI CI/CD Automation Runner.

Skrip ini mengotomatiskan proses DAST scanning di pipeline CI/CD (GitHub Actions / GitLab CI):
1. Menunggu orchestrator DAST-AI aktif (healthcheck).
2. Memulai proses pemindaian ke target URL.
3. Melakukan polling status hingga pemindaian selesai.
4. Menghasilkan ringkasan laporan di konsol, file JSON/Markdown, dan GitHub Actions Step Summary.
5. Menentukan status lolos/gagal (exit code 0 atau 1) berdasarkan ambang batas tingkat keparahan (fail-on threshold).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any

SEVERITY_SCORES: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def http_get(url: str, timeout: int = 10) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "DAST-AI-CI-Runner/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        content = response.read().decode("utf-8")
        return json.loads(content)


def http_post(url: str, payload: dict[str, Any], timeout: int = 15) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "DAST-AI-CI-Runner/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        content = response.read().decode("utf-8")
        return json.loads(content)


def wait_for_orchestrator(api_url: str, max_wait_seconds: int = 60) -> bool:
    health_url = f"{api_url.rstrip('/')}/health"
    print(f"[*] Menghubungi DAST-AI Orchestrator di {health_url}...")
    start_time = time.time()
    while time.time() - start_time < max_wait_seconds:
        try:
            res = http_get(health_url, timeout=3)
            if res.get("status") == "ok":
                print(f"[+] Orchestrator siap! (Environment: {res.get('environment')}, LLM Configured: {res.get('llm_configured')})")
                return True
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
        time.sleep(2)
    print(f"[-] Gagal terhubung ke DAST-AI Orchestrator dalam waktu {max_wait_seconds} detik.")
    return False


def build_markdown_report(target_url: str, scan_data: dict[str, Any], failed: bool, fail_reason: str) -> str:
    if not isinstance(scan_data, dict):
        scan_data = {"scan_id": "N/A", "state": "invalid_response", "report": {}}

    scan_id = scan_data.get("scan_id", "N/A")
    state = scan_data.get("state", "unknown")
    report = scan_data.get("report") if isinstance(scan_data.get("report"), dict) else {}
    total_alerts = report.get("total_alerts", 0)
    true_positives = report.get("true_positive", 0)
    false_positives = report.get("false_positive", 0)
    needs_review = report.get("needs_review", 0)
    findings = report.get("findings", [])
    limitations = report.get("limitations", [])

    if state == "blocked":
        status_badge = "🚫 **BLOCKED**"
        banner_callout = f"> [!WARNING]\n> **DAST Scan Terblokir**: {fail_reason}"
    elif state == "inconclusive":
        status_badge = "⚠️ **INCONCLUSIVE**"
        banner_callout = f"> [!WARNING]\n> **DAST Scan Tidak Konklusif**: {fail_reason}"
    elif state == "failed":
        status_badge = "❌ **FAILED**"
        banner_callout = f"> [!CAUTION]\n> **DAST Scan Gagal**: {fail_reason}"
    elif failed:
        status_badge = "❌ **FAILED**"
        banner_callout = f"> [!CAUTION]\n> **DAST Scan Gagal**: {fail_reason}"
    else:
        status_badge = "✅ **PASSED**"
        banner_callout = "> [!NOTE]\n> **DAST Scan Berhasil**: Tidak ditemukan kerentanan di atas ambang batas toleransi."

    md = [
        "# 🛡️ DAST-AI Security Scan Report",
        "",
        banner_callout,
        "",
        "### 📋 Ringkasan Pemindaian",
        f"- **Target URL:** `{target_url}`",
        f"- **Scan ID:** `{scan_id}`",
        f"- **Status Pipeline:** {status_badge}",
        f"- **Waktu Selesai:** `{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}`",
        "",
        "### 📊 Metrik Temuan",
        "| Total Alerts ZAP | 🔴 True Positives (Terkonfirmasi) | 🟢 False Positives (Dieliminasi) | 🟡 Perlu Verifikasi Manual |",
        "| :---: | :---: | :---: | :---: |",
        f"| **{total_alerts}** | **{true_positives}** | **{false_positives}** | **{needs_review}** |",
        "",
    ]

    if limitations:
        md.append("### ⚠️ Keterbatasan Pemindaian")
        for lim in limitations:
            md.append(f"- {lim}")
        md.append("")

    if findings:
        md.append("### 🔎 Rincian Temuan Keamanan")
        md.append("")
        for f in findings:
            verdict = f.get("verdict", "unknown")
            severity = (f.get("severity") or "info").upper()
            title = f.get("title", "Unknown Finding")
            alert_id = f.get("alert_id", "")
            cwe = f.get("cwe")
            cwe_str = f" (CWE-{cwe})" if cwe else ""
            confidence = f.get("confidence", 0)

            icon = "🔴" if verdict == "true_positive" else ("🟢" if verdict == "likely_false_positive" else "🟡")

            md.append(f"<details><summary>{icon} <b>[{severity}] {title}{cwe_str}</b> — <i>Verdict: {verdict} (Confidence: {confidence:.0%})</i></summary>")
            md.append("")
            md.append(f"- **Alert ID:** `{alert_id}`")
            md.append(f"- **Severity:** `{severity}`")
            md.append(f"- **Verdict:** `{verdict}`")
            if f.get("owasp_top10"):
                md.append(f"- **OWASP Category:** `{f.get('owasp_top10')}`")
            md.append(f"- **Analisis / Alasan:** {f.get('reasoning', '-')}")
            if f.get("evidence_quote"):
                md.append(f"- **Bukti Cuplikan:** `{f.get('evidence_quote')}`")

            fix = f.get("fix")
            if fix and isinstance(fix, dict):
                md.append("")
                md.append("**Saran Perbaikan / Patch:**")
                md.append(f"> {fix.get('summary', '')}")
                if fix.get("code_patch"):
                    lang = fix.get("language") or ""
                    md.append(f"```{lang}\n{fix.get('code_patch')}\n```")
                if fix.get("caveats"):
                    md.append(f"*Catatan perbaikan:* {fix.get('caveats')}")

            steps = f.get("verification_steps") or []
            if steps:
                md.append("")
                md.append("**Langkah Verifikasi:**")
                for s in steps:
                    md.append(f"1. {s}")

            md.append("</details>")
            md.append("")
    elif state == "done":
        md.append("_Tidak ada temuan alert yang terdeteksi._")
        md.append("")

    return "\n".join(md)


def evaluate_findings(findings: list[dict[str, Any]], fail_on: str) -> tuple[bool, str]:
    if fail_on == "none":
        return False, ""

    threshold = SEVERITY_SCORES.get(fail_on, 3)

    violating_findings = []
    for f in findings:
        verdict = f.get("verdict")
        sev = (f.get("severity") or "info").lower()
        score = SEVERITY_SCORES.get(sev, 0)

        if fail_on == "any":
            if verdict == "true_positive":
                violating_findings.append(f)
        elif verdict == "true_positive" and score >= threshold:
            violating_findings.append(f)

    if violating_findings:
        titles = ", ".join(f"[{f.get('severity', '').upper()}] {f.get('title')}" for f in violating_findings[:3])
        if len(violating_findings) > 3:
            titles += f" (+{len(violating_findings) - 3} lainnya)"
        return True, f"Ditemukan {len(violating_findings)} kerentanan terkonfirmasi (true positive) dengan tingkat keparahan >= {fail_on.upper()}: {titles}"

    return False, ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DAST-AI CI Security Scan Runner")
    parser.add_argument("--target-url", required=True, help="URL target aplikasi yang akan dipindai")
    parser.add_argument("--framework", default="unknown", help="Framework target (mis. fastapi, node-express, laravel)")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000", help="URL API DAST-AI Orchestrator")
    parser.add_argument("--poll-interval", type=int, default=5, help="Interval polling status dalam detik")
    parser.add_argument("--timeout", type=int, default=600, help="Batas waktu maksimal pemindaian dalam detik")
    parser.add_argument("--wait-ready", type=int, default=60, help="Waktu tunggu orchestrator siap dalam detik")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "any", "none"],
        default="high",
        help="Ambang batas severity untuk menggagalkan CI (default: high)",
    )
    parser.add_argument(
        "--scan-mode",
        choices=["passive", "active", "full"],
        default="passive",
        help="Mode pemindaian: passive (aman, tanpa fuzzing/attack), active, atau full (default: passive)",
    )
    parser.add_argument(
        "--vercel-bypass-secret",
        default=os.environ.get("VERCEL_BYPASS_SECRET", ""),
        help="Secret token untuk mem-bypass Vercel Deployment Protection (x-vercel-protection-bypass). Disarankan melalui env var VERCEL_BYPASS_SECRET.",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="Header HTTP kustom (format 'Key: Value'). Dapat digunakan berulang kali.",
    )
    parser.add_argument("--exclude-patterns", default="", help="Pola regex URL yang dikecualikan (pisahkan koma)")
    parser.add_argument("--output-json", default="", help="File path untuk menyimpan laporan JSON")
    parser.add_argument("--output-md", default="", help="File path untuk menyimpan laporan Markdown")

    args = parser.parse_args(argv)

    bypass_secret = args.vercel_bypass_secret or os.environ.get("VERCEL_BYPASS_SECRET", "")

    print("=" * 65)
    print("           🛡️  DAST-AI AUTOMATED SECURITY SCANNER")
    print("=" * 65)
    print(f"Target URL:        {args.target_url}")
    print(f"Target Framework:  {args.framework}")
    print(f"Orchestrator API:  {args.api_url}")
    print(f"Scan Mode:         {args.scan_mode.upper()}")
    print(f"Fail-On Threshold: {args.fail_on.upper()}")
    if bypass_secret:
        print("Vercel Bypass:     Enabled (Header injected - value masked)")
    print("-" * 65)

    # 1. Pastikan orchestrator aktif (Exit 3 jika tidak dapat terhubung)
    if not wait_for_orchestrator(args.api_url, max_wait_seconds=args.wait_ready):
        return 3

    # 2. Kirim permintaan pembuatan scan
    scan_url = f"{args.api_url.rstrip('/')}/scans"
    excludes = [p.strip() for p in args.exclude_patterns.split(",") if p.strip()]

    custom_headers: dict[str, str] = {}
    if bypass_secret:
        custom_headers["x-vercel-protection-bypass"] = bypass_secret
        custom_headers["x-vercel-set-bypass-cookie"] = "true"
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            custom_headers[k.strip()] = v.strip()

    payload = {
        "target_url": args.target_url,
        "framework": args.framework,
        "exclude_patterns": excludes,
        "scan_mode": args.scan_mode,
        "custom_headers": custom_headers,
    }

    try:
        print(f"[*] Mengirim permintaan scan ke {scan_url}...")
        init_res = http_post(scan_url, payload)
        scan_id = init_res.get("scan_id")
        if not scan_id:
            print(f"[-] Format respon tidak valid: {init_res}")
            return 3
        print(f"[+] Pemindaian berhasil dijadwalkan! Scan ID: {scan_id}")
    except Exception as e:
        print(f"[-] Gagal membuat permintaan scan: {e}")
        return 3

    # 3. Polling status scan hingga selesai (Hentikan segera pada status terminal)
    status_url = f"{scan_url}/{scan_id}"
    start_time = time.time()
    scan_data: dict[str, Any] = {}
    terminal_state: str = ""

    in_progress_states = {
        "queued",
        "preflight",
        "spidering",
        "passive_scanning",
        "active_scanning",
        "analyzing",
    }
    terminal_states = {"done", "blocked", "inconclusive", "failed"}
    consecutive_poll_errors = 0
    max_consecutive_poll_errors = 5

    print("[*] Memulai pemantauan status scan...")
    while time.time() - start_time < args.timeout:
        try:
            scan_data = http_get(status_url)
            consecutive_poll_errors = 0

            if not isinstance(scan_data, dict):
                print(f"[!] Format respons status tidak valid (bukan JSON object): {scan_data}")
                terminal_state = "invalid_api_response"
                break

            state = scan_data.get("state")
            elapsed = int(time.time() - start_time)
            mins, secs = divmod(elapsed, 60)
            timestamp_str = f"{mins:02d}:{secs:02d}"

            print(f"[{timestamp_str}] State: {state.upper() if state else 'UNKNOWN'}")

            if state in terminal_states:
                terminal_state = state
                print(f"[+] Pemindaian mencapai status terminal '{state.upper()}' dalam {timestamp_str}!")
                break
            elif state not in in_progress_states:
                terminal_state = str(state) if state else "unknown_or_empty"
                print(f"[-] Terdeteksi status tidak dikenal/tidak valid '{terminal_state}' dalam {timestamp_str}!")
                break

        except Exception as e:
            consecutive_poll_errors += 1
            print(f"[!] Warning saat polling status ({consecutive_poll_errors}/{max_consecutive_poll_errors}): {e}")
            if consecutive_poll_errors >= max_consecutive_poll_errors:
                print(f"[-] Polling dihentikan karena {max_consecutive_poll_errors} kegagalan berturut-turut.")
                terminal_state = "polling_failed"
                break

        time.sleep(args.poll_interval)
    else:
        print(f"[-] Pemindaian timeout setelah melebihi batas waktu {args.timeout} detik.")
        terminal_state = "timeout"

    # 4. Evaluasi hasil berdasarkan status terminal & tentukan exit code
    safe_scan_data = scan_data if isinstance(scan_data, dict) else {
        "scan_id": scan_id if "scan_id" in locals() and scan_id else "N/A",
        "state": terminal_state,
        "error": "Respons status scan bukan JSON object yang valid",
        "report": {},
    }
    report = safe_scan_data.get("report") if isinstance(safe_scan_data.get("report"), dict) else {}
    findings = report.get("findings", [])
    failed = False
    fail_reason = ""
    exit_code = 0

    if terminal_state == "failed":
        err = safe_scan_data.get("error", "Alasan tidak diketahui")
        print(f"[-] Pemindaian GAGAL: {err}")
        failed = True
        fail_reason = f"Kegagalan internal scanner/pipeline: {err}"
        exit_code = 3

    elif terminal_state == "blocked":
        target_health = report.get("target_health") or {}
        diag = target_health.get("diagnostic_message") or "Target memblokir pemindaian (Vercel challenge / auth wall / WAF / redirect out of scope)."
        fail_reason = f"Target memblokir pemindaian: {diag}"
        print(f"\n🚫 [CI BLOCKED] {fail_reason}")
        failed = True
        exit_code = 2

    elif terminal_state == "inconclusive":
        limitations = report.get("limitations") or []
        lim_str = "; ".join(limitations) if limitations else "Crawling tidak menemukan endpoint yang dapat diuji atau bukti pengujian tidak mencukupi."
        fail_reason = f"Pemindaian tidak konklusif: {lim_str}"
        print(f"\n⚠️ [CI INCONCLUSIVE] {fail_reason}")
        failed = True
        exit_code = 2

    elif terminal_state == "timeout":
        fail_reason = f"Pemindaian timeout setelah melebihi batas waktu {args.timeout} detik."
        print(f"\n[-] {fail_reason}")
        failed = True
        exit_code = 3

    elif terminal_state == "polling_failed":
        fail_reason = "Polling status gagal berulang kali karena orchestrator tidak dapat dihubungi."
        print(f"\n[-] {fail_reason}")
        failed = True
        exit_code = 3

    elif terminal_state == "done":
        failed, fail_reason = evaluate_findings(findings, args.fail_on)
        if failed:
            print(f"\n❌ [CI FAILED] {fail_reason}")
            exit_code = 1
        else:
            print(f"\n✅ [CI PASSED] Pemindaian keamanan memenuhi ambang batas ({args.fail_on.upper()}).")
            exit_code = 0

    else:
        fail_reason = f"Status terminal pemindaian tidak dikenal atau tidak valid: '{terminal_state}'"
        print(f"\n[-] {fail_reason}")
        failed = True
        exit_code = 3

    # 5. Cetak ringkasan di konsol
    print("\n" + "=" * 65)
    print("                    RINGKASAN HASIL PEMINDAIAN")
    print("=" * 65)
    print(f"Status Terminal:        {terminal_state.upper()}")
    print(f"Total Alerts ZAP:       {report.get('total_alerts', 0)}")
    print(f"🔴 True Positives:      {report.get('true_positive', 0)}")
    print(f"🟢 False Positives:     {report.get('false_positive', 0)}")
    print(f"🟡 Perlu Review Manual: {report.get('needs_review', 0)}")
    print("-" * 65)

    if findings:
        print("Daftar Temuan:")
        for f in findings:
            sev = (f.get("severity") or "info").upper()
            verdict = f.get("verdict")
            print(f" - [{sev}] {f.get('title')} -> {verdict} (Confidence: {f.get('confidence', 0):.0%})")
    elif terminal_state == "done":
        print("Tidak ada temuan kerentanan yang terdeteksi.")
    else:
        print(f"Pemeriksaan dihentikan pada status: {terminal_state.upper()}")
    print("=" * 65)

    # 6. Format Markdown Report & Tulis Output
    markdown_report = build_markdown_report(args.target_url, safe_scan_data, failed, fail_reason)

    if args.output_json:
        try:
            with open(args.output_json, "w", encoding="utf-8") as f:
                json.dump(safe_scan_data, f, indent=2)
            print(f"[+] Laporan JSON disimpan di: {args.output_json}")
        except OSError as e:
            print(f"[!] Gagal menyimpan laporan JSON: {e}")

    if args.output_md:
        try:
            with open(args.output_md, "w", encoding="utf-8") as f:
                f.write(markdown_report)
            print(f"[+] Laporan Markdown disimpan di: {args.output_md}")
        except OSError as e:
            print(f"[!] Gagal menyimpan laporan Markdown: {e}")

    step_summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary_path:
        try:
            with open(step_summary_path, "a", encoding="utf-8") as f:
                f.write("\n" + markdown_report + "\n")
            print("[+] Laporan berhasil ditambahkan ke GitHub Actions Step Summary!")
        except OSError as e:
            print(f"[!] Gagal menulis ke GITHUB_STEP_SUMMARY: {e}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
