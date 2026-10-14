import re
import time
from typing import Callable

from zapv2 import ZAPv2

from .config import settings

# Jangan pernah crawl/serang endpoint yang berefek destruktif atau memutus sesi.
DEFAULT_EXCLUDES = [r".*logout.*", r".*signout.*", r".*/delete.*", r".*/destroy.*", r".*/reset-db.*"]


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

    zap.core.new_session(name="dast-ai", overwrite=True)
    zap.core.set_mode("protect")  # ZAP hanya boleh menyerang URL yang in-scope
    ctx_id = zap.context.new_context(ctx)
    zap.context.include_in_context(ctx, re.escape(target.rstrip("/")) + ".*")
    for pat in DEFAULT_EXCLUDES + (extra_excludes or []):
        zap.context.exclude_from_context(ctx, pat)

    # Injeksi custom headers (mis. x-vercel-protection-bypass) via ZAP Replacer
    all_headers = dict(custom_headers or {})
    if settings.vercel_bypass_secret and "x-vercel-protection-bypass" not in all_headers:
        all_headers["x-vercel-protection-bypass"] = settings.vercel_bypass_secret
        all_headers["x-vercel-set-bypass-cookie"] = "true"

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
            )
        except Exception:
            pass

    # Throttling agar server uji tidak kewalahan
    zap.ascan.set_option_thread_per_host(settings.threads_per_host)
    zap.ascan.set_option_delay_in_ms(settings.delay_ms)
    zap.ascan.set_option_max_scan_duration_in_mins(settings.max_scan_minutes)
    zap.spider.set_option_max_duration(settings.max_spider_minutes)

    # 1) Mapping endpoint (spider) + passive scan
    sid = zap.spider.scan(target, contextname=ctx, subtreeonly=True)
    _wait(lambda: int(zap.spider.status(sid)), 100,
          settings.max_spider_minutes * 60 + 30, lambda: zap.spider.stop(sid))
    _wait(lambda: 100 if int(zap.pscan.records_to_scan) == 0 else 0, 100, 120, lambda: None)

    # 2) Active scan terkontrol (HANYA dijalankan bila mode 'active' atau 'full')
    if scan_mode in ("active", "full"):
        aid = zap.ascan.scan(target, contextid=ctx_id,
                             scanpolicyname=settings.scan_policy or None)
        _wait(lambda: int(zap.ascan.status(aid)), 100,
              settings.max_scan_minutes * 60 + 30, lambda: zap.ascan.stop(aid))

    return zap.core.alerts(baseurl=target, start=0, count=500)
