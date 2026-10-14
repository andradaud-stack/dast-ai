import logging
import re
import time
from typing import Callable
from urllib.parse import urlparse

import httpx
from zapv2 import ZAPv2

from .config import settings
from .guardrails import build_zap_scope_regex, is_url_in_scope
from .sanitizer import prepare_alerts
from .schemas import CoverageMetrics, TargetHealth, TechnicalAlert

logger = logging.getLogger(__name__)

# Endpoint destruktif yang dilarang keras untuk dikunjungi atau diuji
DEFAULT_EXCLUDES = [
    r".*logout.*",
    r".*signout.*",
    r".*/delete.*",
    r".*/destroy.*",
    r".*/reset.*",
    r".*/reset-db.*",
    r".*/drop.*",
    r".*/truncate.*",
    r".*/purge.*",
    r".*/cancel.*",
    r".*/remove.*",
    r".*/update.*",
    r".*/create.*",
]


def _zap() -> ZAPv2:
    return ZAPv2(
        apikey=settings.zap_api_key,
        proxies={"http": settings.zap_url, "https": settings.zap_url},
    )


def check_zap_connectivity() -> bool:
    """Memeriksa apakah daemon OWASP ZAP dapat dihubungi dan merespons."""
    try:
        zap = _zap()
        _ = zap.core.version
        return True
    except Exception as e:
        logger.warning("Koneksi ke ZAP daemon di %s gagal: %s", settings.zap_url, e)
        return False


def check_target_health(target_url: str, custom_headers: dict[str, str] | None = None) -> TargetHealth:
    """
    Melakukan pre-flight HTTP check ke target:
    - Memverifikasi apakah target dapat dijangkau
    - Memeriksa redirect ke luar scope
    - Mendeteksi Vercel Deployment Protection, login wall, atau blokir WAF
    """
    req_headers = {
        "User-Agent": "DAST-AI-Scanner/1.0",
        "Accept": "*/*",
    }
    bypass_secret = getattr(settings, "vercel_bypass_secret", "") or getattr(settings, "vercel_protection_bypass_secret", "")
    if bypass_secret:
        req_headers["x-vercel-protection-bypass"] = bypass_secret

    if custom_headers:
        for k, v in custom_headers.items():
            if k.lower() not in ("host", "authorization"):
                req_headers[k] = v

    try:
        with httpx.Client(follow_redirects=False, timeout=settings.preflight_timeout_seconds, verify=False) as client:
            resp = client.get(target_url, headers=req_headers)

            # 1. Pengecekan Redirect
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if location and not is_url_in_scope(location, target_url):
                    return TargetHealth(
                        accessible=False,
                        status_code=resp.status_code,
                        final_url=location,
                        is_redirected=True,
                        redirect_in_scope=False,
                        is_protected=True,
                        protection_type="redirect_out_of_scope",
                        diagnostic_message=f"Target mengalihkan ke domain di luar scope: {location}",
                    )

            # 2. Pengecekan Vercel Deployment Protection
            is_vercel = (
                "x-vercel-challenge" in resp.headers
                or "x-vercel-id" in resp.headers
                or "Vercel Deployment Protection" in resp.text
            )
            if resp.status_code == 401 and is_vercel:
                return TargetHealth(
                    accessible=False,
                    status_code=401,
                    final_url=str(resp.url),
                    is_protected=True,
                    protection_type="vercel_challenge",
                    diagnostic_message="Target terlindungi oleh Vercel Deployment Protection (HTTP 401 Challenge).",
                )

            # 3. Pengecekan HTTP Auth atau WAF / Forbidden
            if resp.status_code == 401:
                return TargetHealth(
                    accessible=False,
                    status_code=401,
                    final_url=str(resp.url),
                    is_protected=True,
                    protection_type="http_auth",
                    diagnostic_message="Target memerlukan autentikasi HTTP (HTTP 401 Unauthorized).",
                )
            if resp.status_code == 403:
                return TargetHealth(
                    accessible=False,
                    status_code=403,
                    final_url=str(resp.url),
                    is_protected=True,
                    protection_type="waf_blocked",
                    diagnostic_message="Target menolak akses (HTTP 403 Forbidden / WAF).",
                )
            if resp.status_code in (502, 503, 504):
                return TargetHealth(
                    accessible=False,
                    status_code=resp.status_code,
                    final_url=str(resp.url),
                    diagnostic_message=f"Target mengalami error gateway (HTTP {resp.status_code}).",
                )

            # Berhasil diakses
            return TargetHealth(
                accessible=True,
                status_code=resp.status_code,
                final_url=str(resp.url),
                is_protected=False,
                diagnostic_message="Target berhasil diakses.",
            )

    except httpx.ConnectTimeout:
        return TargetHealth(accessible=False, diagnostic_message="Timeout saat menghubungkan ke target.")
    except httpx.ConnectError as e:
        return TargetHealth(accessible=False, diagnostic_message=f"Gagal menghubungkan ke target: {e}")
    except Exception as e:
        return TargetHealth(accessible=False, diagnostic_message=f"Error saat pre-flight check target: {e}")


def _wait(poll: Callable[[], int], done: int, timeout_s: int, on_timeout: Callable[[], None]) -> bool:
    """Menunggu polling hingga selesai atau timeout tercapai."""
    start = time.time()
    while True:
        try:
            val = poll()
            if val >= done:
                return True
        except Exception as e:
            logger.debug("Error saat polling ZAP: %s", e)

        if time.time() - start > timeout_s:
            on_timeout()
            return False
        time.sleep(2)


def _setup_zap_replacer_headers(zap: ZAPv2, target_scope_regex: str, custom_headers: dict[str, str] | None = None) -> None:
    """Injeksi custom headers dengan batasi URL regex agar tidak bocor ke origin lain."""
    all_headers = dict(custom_headers or {})
    bypass_secret = getattr(settings, "vercel_bypass_secret", "") or getattr(settings, "vercel_protection_bypass_secret", "")
    if bypass_secret and "x-vercel-protection-bypass" not in all_headers:
        all_headers["x-vercel-protection-bypass"] = bypass_secret
        all_headers["x-vercel-set-bypass-cookie"] = "true"

    try:
        existing_rules = zap.replacer.rules
        if isinstance(existing_rules, list):
            for r in existing_rules:
                desc = r.get("description", "")
                if desc.startswith("hdr_inject_"):
                    zap.replacer.remove_rule(desc)
    except Exception:
        pass

    for idx, (hdr_name, hdr_val) in enumerate(all_headers.items()):
        rule_desc = f"hdr_inject_{idx}_{hdr_name.lower()}"
        try:
            zap.replacer.add_rule(
                description=rule_desc,
                enabled="true",
                matchtype="REQ_HEADER",
                matchregex="false",
                matchstring=hdr_name,
                replacement=hdr_val,
                url=target_scope_regex,
            )
        except Exception:
            pass


class ScanExecutionResult:
    def __init__(
        self,
        target_health: TargetHealth,
        coverage: CoverageMetrics,
        raw_alerts: list[dict],
        technical_alerts: list[TechnicalAlert],
        verdict_status: str,
        limitations: list[str],
    ):
        self.target_health = target_health
        self.coverage = coverage
        self.raw_alerts = raw_alerts
        self.technical_alerts = technical_alerts
        self.verdict_status = verdict_status
        self.limitations = limitations


def execute_scan(
    target: str,
    scan_mode: str = "passive",
    extra_excludes: list[str] | None = None,
    custom_headers: dict[str, str] | None = None,
    scan_policy: str | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> ScanExecutionResult:
    """
    Eksekusi lifecycle scanning lengkap dengan pre-flight, isolasi scope, dan coverage metrics.
    """
    limitations: list[str] = []
    durations: dict[str, float] = {}

    def report_step(step: str):
        if progress_callback:
            progress_callback(step)

    # 1. Pre-flight Check
    report_step("preflight")
    t0 = time.time()
    health = check_target_health(target, custom_headers)
    durations["preflight"] = round(time.time() - t0, 2)

    coverage = CoverageMetrics(
        duration_seconds=durations,
    )

    if not health.accessible:
        if health.is_protected:
            verdict = "blocked"
            limitations.append(f"Scan diblokir oleh proteksi target: {health.diagnostic_message}")
        else:
            verdict = "inconclusive"
            limitations.append(f"Target tidak dapat diakses secara normal: {health.diagnostic_message}")
        coverage.limitations_disclaimer = "; ".join(limitations)
        return ScanExecutionResult(
            target_health=health,
            coverage=coverage,
            raw_alerts=[],
            technical_alerts=[],
            verdict_status=verdict,
            limitations=limitations,
        )

    # 2. Validasi Koneksi ZAP
    if not check_zap_connectivity():
        raise RuntimeError(f"OWASP ZAP daemon tidak dapat dihubungi di {settings.zap_url}. Pastikan ZAP berjalan.")

    zap = _zap()
    ctx = f"dast_{int(time.time())}"

    # 3. Setup Konteks dan Scope Strict
    target_clean = target.rstrip("/")
    target_scope_regex = re.escape(target_clean) + ".*"

    zap.core.new_session(name=ctx, overwrite=True)
    zap.core.set_mode("protect")
    ctx_id = zap.context.new_context(ctx)

    scope_regex = build_zap_scope_regex(target)
    zap.context.include_in_context(ctx, scope_regex)

    all_excludes = DEFAULT_EXCLUDES + (extra_excludes or [])
    for pat in all_excludes:
        zap.context.exclude_from_context(ctx, pat)

    # Injeksi Replacer Header terisolasi ke target
    _setup_zap_replacer_headers(zap, target_scope_regex, custom_headers)

    # Proteksi Spider: Matikan POST form
    zap.spider.set_option_post_form(False)

    # Konfigurasi Throttling & Limit
    zap.ascan.set_option_thread_per_host(settings.threads_per_host)
    zap.ascan.set_option_delay_in_ms(settings.delay_ms)
    zap.ascan.set_option_max_scan_duration_in_mins(settings.max_scan_minutes)
    zap.spider.set_option_max_duration(settings.max_spider_minutes)

    discovered_urls: set[str] = set()

    # 4. Tahap Discovery (Spider) & Passive Scan
    if scan_mode in ("passive", "full"):
        report_step("spidering")
        t_sp = time.time()
        sid = zap.spider.scan(target, contextname=ctx, subtreeonly=True)
        spider_completed = _wait(
            lambda: int(zap.spider.status(sid)),
            100,
            settings.max_spider_minutes * 60 + 15,
            lambda: zap.spider.stop(sid),
        )
        durations["spider"] = round(time.time() - t_sp, 2)
        coverage.spider_status = "completed" if spider_completed else "timeout"

        try:
            urls = zap.spider.results(sid)
            if isinstance(urls, list):
                discovered_urls.update(urls)
        except Exception as e:
            logger.debug("Gagal mengambil spider results: %s", e)

        report_step("passive_scanning")
        t_ps = time.time()
        ps_completed = _wait(
            lambda: 100 if int(zap.pscan.records_to_scan) == 0 else 0,
            100,
            90,
            lambda: None,
        )
        durations["passive_scan"] = round(time.time() - t_ps, 2)
        coverage.passive_scan_status = "completed" if ps_completed else "timeout"
    else:
        coverage.spider_status = "skipped_active_only"
        coverage.passive_scan_status = "skipped_active_only"
        limitations.append("Spider dan passive scan dilewati karena mode 'active' dipilih secara eksplisit.")

    try:
        core_urls = zap.core.urls(baseurl=target)
        if isinstance(core_urls, list):
            discovered_urls.update(core_urls)
    except Exception as e:
        logger.debug("Gagal mengambil core urls: %s", e)

    discovered_urls.add(target)

    # 5. Tahap Active Scan (hanya jika mode 'active' atau 'full')
    active_rules_run = 0
    if scan_mode in ("active", "full"):
        report_step("active_scanning")
        t_as = time.time()
        policy = scan_policy or settings.scan_policy or None
        aid = zap.ascan.scan(target, contextid=ctx_id, scanpolicyname=policy)
        ascan_completed = _wait(
            lambda: int(zap.ascan.status(aid)),
            100,
            settings.max_scan_minutes * 60 + 30,
            lambda: zap.ascan.stop(aid),
        )
        durations["active_scan"] = round(time.time() - t_as, 2)
        coverage.active_scan_status = "completed" if ascan_completed else "timeout"

        try:
            progress = zap.ascan.scan_progress(aid)
            if isinstance(progress, list):
                active_rules_run = len(progress)
            elif isinstance(progress, dict):
                active_rules_run = len(progress.get("HostProcess", []))
        except Exception as e:
            logger.debug("Gagal membaca ascan progress: %s", e)
            active_rules_run = 1
    else:
        coverage.active_scan_status = "skipped_passive_mode"
        limitations.append(
            "Active scanning (SQLi, XSS, RCE, CSRF) TIDAK dijalankan karena scanner berada dalam mode 'passive'."
        )

    coverage.active_scan_rules_run = active_rules_run

    # 6. Ekstraksi Alert dan Pembersihan
    report_step("analyzing")
    raw_alerts = zap.core.alerts(baseurl=target, start=0, count=500)
    cleaned_alerts = prepare_alerts(raw_alerts)

    technical_alerts = [
        TechnicalAlert(
            alert_id=item["alert_id"],
            plugin_id=item.get("plugin_id", ""),
            name=item["name"],
            risk=item["risk"],
            confidence=item["zap_confidence"],
            cwe=item.get("cwe") or None,
            wasc=item.get("wasc") or None,
            url=item["url"],
            method=item["method"],
            param=item.get("param") or None,
            attack=item.get("attack") or None,
            evidence=item.get("evidence") or None,
            zap_description=item.get("zap_description") or None,
            solution=item.get("solution") or None,
            reference=item.get("reference") or None,
            source=item.get("source", "zap"),
        )
        for item in cleaned_alerts
    ]

    discovered_list = sorted(list(discovered_urls))
    endpoints = sorted(list({urlparse(u).path for u in discovered_list if u}))

    coverage.urls_discovered = discovered_list[:100]
    coverage.total_urls_discovered = len(discovered_list)
    coverage.endpoints_tested = endpoints[:50]
    coverage.total_endpoints_tested = len(endpoints)
    coverage.duration_seconds = durations

    if len(discovered_list) <= 1 and coverage.spider_status == "completed":
        verdict = "inconclusive"
        limitations.append(
            "Discovery hanya menemukan 1 URL/endpoint root. Periksa apakah aplikasi membutuhkan login atau JavaScript crawling."
        )
    else:
        verdict = "completed"

    coverage.limitations_disclaimer = "; ".join(limitations) if limitations else "Tidak ada batasan signifikan."

    return ScanExecutionResult(
        target_health=health,
        coverage=coverage,
        raw_alerts=raw_alerts,
        technical_alerts=technical_alerts,
        verdict_status=verdict,
        limitations=limitations,
    )


def run_scan(
    target: str,
    extra_excludes: list[str] | None = None,
    scan_mode: str = "passive",
    custom_headers: dict[str, str] | None = None,
) -> list[dict]:
    """
    Fungsi kompatibilitas penuh dengan interface run_scan lama:
    - Mode 'protect'
    - Injeksi header via ZAP replacer dengan url target regex isolation
    - Matikan spider post_form
    - Mode passive / active / full
    """
    zap = _zap()
    ctx = "target"
    target_clean = target.rstrip("/")
    target_scope_regex = re.escape(target_clean) + ".*"

    zap.core.new_session(name="dast-ai", overwrite=True)
    zap.core.set_mode("protect")

    ctx_id = zap.context.new_context(ctx)
    zap.context.include_in_context(ctx, target_scope_regex)
    for pat in DEFAULT_EXCLUDES + (extra_excludes or []):
        zap.context.exclude_from_context(ctx, pat)

    _setup_zap_replacer_headers(zap, target_scope_regex, custom_headers)

    zap.spider.set_option_post_form(False)
    zap.spider.set_option_max_duration(settings.max_spider_minutes)

    sid = zap.spider.scan(target, contextname=ctx, subtreeonly=True)
    _wait(lambda: int(zap.spider.status(sid)), 100,
          settings.max_spider_minutes * 60 + 30, lambda: zap.spider.stop(sid))
    _wait(lambda: 100 if int(zap.pscan.records_to_scan) == 0 else 0, 100, 120, lambda: None)

    if scan_mode in ("active", "full"):
        zap.ascan.set_option_thread_per_host(settings.threads_per_host)
        zap.ascan.set_option_delay_in_ms(settings.delay_ms)
        zap.ascan.set_option_max_scan_duration_in_mins(settings.max_scan_minutes)

        aid = zap.ascan.scan(target, contextid=ctx_id,
                             scanpolicyname=settings.scan_policy or None)
        _wait(lambda: int(zap.ascan.status(aid)), 100,
              settings.max_scan_minutes * 60 + 30, lambda: zap.ascan.stop(aid))

    return zap.core.alerts(baseurl=target, start=0, count=500)
