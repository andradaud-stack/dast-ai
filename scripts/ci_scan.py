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
    scan_id = scan_data.get("scan_id", "N/A")
    report = scan_data.get("report") or {}
    total_alerts = report.get("total_alerts", 0)
    true_positives = report.get("true_positive", 0)
    false_positives = report.get("false_positive", 0)
    needs_review = report.get("needs_review", 0)
    findings = report.get("findings", [])

    status_badge = "❌ **FAILED**" if failed else "✅ **PASSED**"
    banner_callout = (
        f"> [!CAUTION]\n> **DAST Scan Gagal**: {fail_reason}"
        if failed
        else "> [!NOTE]\n> **DAST Scan Berhasil**: Tidak ditemukan kerentanan di atas ambang batas toleransi."
    )

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
    else:
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


def main() -> int:
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
    parser.add_argument("--exclude-patterns", default="", help="Pola regex URL yang dikecualikan (pisahkan koma)")
    parser.add_argument("--output-json", default="", help="File path untuk menyimpan laporan JSON")
    parser.add_argument("--output-md", default="", help="File path untuk menyimpan laporan Markdown")

    args = parser.parse_args()

    print("=" * 65)
    print("           🛡️  DAST-AI AUTOMATED SECURITY SCANNER")
    print("=" * 65)
    print(f"Target URL:        {args.target_url}")
    print(f"Target Framework:  {args.framework}")
    print(f"Orchestrator API:  {args.api_url}")
    print(f"Fail-On Threshold: {args.fail_on.upper()}")
    print("-" * 65)

    # 1. Pastikan orchestrator aktif
    if not wait_for_orchestrator(args.api_url, max_wait_seconds=args.wait_ready):
        return 1

    # 2. Kirim permintaan pembuatan scan
    scan_url = f"{args.api_url.rstrip('/')}/scans"
    excludes = [p.strip() for p in args.exclude_patterns.split(",") if p.strip()]
    payload = {
        "target_url": args.target_url,
        "framework": args.framework,
        "exclude_patterns": excludes,
    }

    try:
        print(f"[*] Mengirim permintaan scan ke {scan_url}...")
        init_res = http_post(scan_url, payload)
        scan_id = init_res.get("scan_id")
        if not scan_id:
            print(f"[-] Format respon tidak valid: {init_res}")
            return 1
        print(f"[+] Pemindaian berhasil dijadwalkan! Scan ID: {scan_id}")
    except Exception as e:
        print(f"[-] Gagal membuat permintaan scan: {e}")
        return 1

    # 3. Polling status scan hingga selesai
    status_url = f"{scan_url}/{scan_id}"
    start_time = time.time()
    scan_data: dict[str, Any] = {}

    print("[*] Memulai pemantauan status scan...")
    while time.time() - start_time < args.timeout:
        try:
            scan_data = http_get(status_url)
            state = scan_data.get("state")
            elapsed = int(time.time() - start_time)
            mins, secs = divmod(elapsed, 60)
            timestamp_str = f"{mins:02d}:{secs:02d}"

            print(f"[{timestamp_str}] State: {state.upper() if state else 'UNKNOWN'}")

            if state == "done":
                print(f"[+] Pemindaian selesai dalam {timestamp_str}!")
                break
            if state == "failed":
                err = scan_data.get("error", "Alasan tidak diketahui")
                print(f"[-] Pemindaian GAGAL: {err}")
                return 1

        except Exception as e:
            print(f"[!] Warning saat polling status: {e}")

        time.sleep(args.poll_interval)
    else:
        print(f"[-] Pemindaian timeout setelah melebihi batas waktu {args.timeout} detik.")
        return 1

    # 4. Evaluasi hasil temuan
    report = scan_data.get("report") or {}
    findings = report.get("findings", [])
    failed, fail_reason = evaluate_findings(findings, args.fail_on)

    # 5. Cetak ringkasan di konsol
    print("\n" + "=" * 65)
    print("                    RINGKASAN HASIL PEMINDAIAN")
    print("=" * 65)
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
    else:
        print("Tidak ada temuan kerentanan yang terdeteksi.")
    print("=" * 65)

    # 6. Format Markdown Report
    markdown_report = build_markdown_report(args.target_url, scan_data, failed, fail_reason)

    # Tulis ke file JSON jika diminta
    if args.output_json:
        try:
            with open(args.output_json, "w", encoding="utf-8") as f:
                json.dump(scan_data, f, indent=2)
            print(f"[+] Laporan JSON disimpan di: {args.output_json}")
        except OSError as e:
            print(f"[!] Gagal menyimpan laporan JSON: {e}")

    # Tulis ke file Markdown jika diminta
    if args.output_md:
        try:
            with open(args.output_md, "w", encoding="utf-8") as f:
                f.write(markdown_report)
            print(f"[+] Laporan Markdown disimpan di: {args.output_md}")
        except OSError as e:
            print(f"[!] Gagal menyimpan laporan Markdown: {e}")

    # Tulis ke GitHub Actions Step Summary jika environment variable tersedia
    step_summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary_path:
        try:
            with open(step_summary_path, "a", encoding="utf-8") as f:
                f.write("\n" + markdown_report + "\n")
            print("[+] Laporan berhasil ditambahkan ke GitHub Actions Step Summary!")
        except OSError as e:
            print(f"[!] Gagal menulis ke GITHUB_STEP_SUMMARY: {e}")

    # 7. Penentuan exit code
    if failed:
        print(f"\n❌ [CI FAILED] {fail_reason}")
        return 1

    print(f"\n✅ [CI PASSED] Pemindaian keamanan memenuhi ambang batas ({args.fail_on.upper()}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
