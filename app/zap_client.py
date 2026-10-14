import re
import time
from typing import Callable

from zapv2 import ZAPv2

from .config import settings

# Jangan pernah crawl/serang endpoint yang berefek destruktif atau memutus sesi.
DEFAULT_EXCLUDES = [
    r".*logout.*",
    r".*signout.*",
    r".*/delete.*",
    r".*/destroy.*",
    r".*/reset.*",
    r".*/drop.*",
    r".*/update.*",
    r".*/create.*",
]


def _zap() -> ZAPv2:
    return ZAPv2(apikey=settings.zap_api_key,
                 proxies={"http": settings.zap_url, "https": settings.zap_url})


def _wait(poll: Callable[[], int], done: int, timeout_s: int, on_timeout: Callable[[], None]):
    start = time.time()
    while poll() < done:
        if time.time() - start > timeout_s:
            on_timeout()
            return
        time.sleep(3)


def run_scan(
    target: str,
    extra_excludes: list[str] | None = None,
    scan_mode: str = "passive",
    custom_headers: dict[str, str] | None = None,
) -> list[dict]:
    zap = _zap()
    ctx = "target"
    target_clean = target.rstrip("/")
    target_scope_regex = re.escape(target_clean) + ".*"

    zap.core.new_session(name="dast-ai", overwrite=True)

    # 1. Enforcement engine mode ZAP:
    # Mode "safe" menonaktifkan seluruh kapabilitas serangan ZAP secara engine-level.
    # Mode "protect" hanya mengizinkan serangan pada URL yang eksplisit terdaftar di context.
    if scan_mode == "passive":
        zap.core.set_mode("safe")
    else:
        zap.core.set_mode("protect")

    ctx_id = zap.context.new_context(ctx)
    zap.context.include_in_context(ctx, target_scope_regex)
    for pat in DEFAULT_EXCLUDES + (extra_excludes or []):
        zap.context.exclude_from_context(ctx, pat)

    # 2. Injeksi custom headers (mis. x-vercel-protection-bypass)
    # PENTING: Batasi parameter 'url' ke target regex agar secret TIDAK bocor ke domain pihak ketiga/CDN
    all_headers = dict(custom_headers or {})
    if settings.vercel_bypass_secret and "x-vercel-protection-bypass" not in all_headers:
        all_headers["x-vercel-protection-bypass"] = settings.vercel_bypass_secret
        all_headers["x-vercel-set-bypass-cookie"] = "true"

    # Bersihkan rule replacer lama jika ada
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
                url=target_scope_regex,  # Isolasi ketat: hanya dikirim ke target, tidak bocor ke origin lain!
            )
        except Exception:
            pass

    # 3. Proteksi Spider: Pastikan spider TIDAK mengirimkan request POST form
    # Ini melindungi database target (seperti TiDB Cloud di DesignLogV2) agar tidak berubah/terisi data uji
    zap.spider.set_option_post_form(False)
    zap.spider.set_option_max_duration(settings.max_spider_minutes)

    # 4. Mapping endpoint (spider) + passive scan
    sid = zap.spider.scan(target, contextname=ctx, subtreeonly=True)
    _wait(lambda: int(zap.spider.status(sid)), 100,
          settings.max_spider_minutes * 60 + 30, lambda: zap.spider.stop(sid))
    _wait(lambda: 100 if int(zap.pscan.records_to_scan) == 0 else 0, 100, 120, lambda: None)

    # 5. Active scan terkontrol (HANYA dijalankan bila scan_mode == 'active' atau 'full')
    if scan_mode in ("active", "full"):
        zap.ascan.set_option_thread_per_host(settings.threads_per_host)
        zap.ascan.set_option_delay_in_ms(settings.delay_ms)
        zap.ascan.set_option_max_scan_duration_in_mins(settings.max_scan_minutes)

        aid = zap.ascan.scan(target, contextid=ctx_id,
                             scanpolicyname=settings.scan_policy or None)
        _wait(lambda: int(zap.ascan.status(aid)), 100,
              settings.max_scan_minutes * 60 + 30, lambda: zap.ascan.stop(aid))

    return zap.core.alerts(baseurl=target, start=0, count=500)
