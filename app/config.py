from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: str = "staging"          # hanya "local" / "staging" yang diizinkan
    allowed_hosts: list[str] = []         # allowlist hostname target (exact hostname atau wildcard *.domain.com)
    require_private_ip: bool = True
    zap_url: str = "http://localhost:8090"
    zap_api_key: str = ""
    llm_api_key: str = ""
    llm_model: str = "claude-sonnet-5-5"
    threads_per_host: int = 2
    delay_ms: int = 200
    max_spider_minutes: int = 5
    max_scan_minutes: int = 20
    scan_policy: str = ""                 # nama scan policy ZAP custom (opsional)

    # Keamanan API Orchestrator & Concurrency
    api_auth_token: str = ""              # Bearer token autentikasi API DAST-AI
    default_scan_mode: str = "passive"    # "passive", "active", "full"
    max_concurrent_scans: int = 2         # Batas scan konkuren untuk mencegah DoS
    max_stored_scans: int = 100           # Batas riwayat scan in-memory
    preflight_timeout_seconds: int = 10   # Timeout pre-flight check target
    verify_tls: bool = True               # Verifikasi sertifikat TLS default AKTIF (Priority 2)

    # Vercel Deployment Protection Bypass
    vercel_bypass_secret: str = ""
    vercel_protection_bypass_secret: str = ""


settings = Settings()
