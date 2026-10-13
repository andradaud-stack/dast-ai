from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: str = "staging"          # hanya "local" / "staging" yang diizinkan
    allowed_hosts: list[str] = []         # allowlist hostname target
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


settings = Settings()
