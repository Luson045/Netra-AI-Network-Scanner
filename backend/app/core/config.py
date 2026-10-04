"""Application configuration loaded from environment variables / .env."""

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Netra AI"
    app_env: str = "local"  # local | docker | test | production
    debug: bool = True
    log_level: str = "INFO"

    # Database: Postgres in docker, SQLite fallback for zero-setup local runs
    database_url: str = "sqlite+aiosqlite:///./data/netguard.db"

    # Ollama is contacted for Deep Scan agent planning/analysis and requested explanations.
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2:3b"
    ollama_timeout_secs: float = 120.0

    # CORS (comma-separated origins)
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Scanner behaviour
    scan_concurrency: int = 64          # max simultaneous socket checks
    connect_timeout: float = 1.5        # seconds per TCP connect check
    poll_interval: float = 2.0          # worker DB polling interval (seconds)
    worker_heartbeat_secs: int = 30     # lease expiry for crashed workers
    target_rate_limit: int = 50         # socket checks/second soft cap

    # Authorisation guardrails
    allow_private_targets: bool = True  # RFC1918/loopback/link-local
    allow_localhost: bool = True        # 127.0.0.0/8, ::1
    target_allowlist: str = ""          # comma-separated extra CIDRs, e.g. "10.0.0.0/8,203.0.113.5/32"
    max_hosts_per_scan: int = 4096      # hard ceiling to prevent runaway scans
    max_ports_per_scan: int = 2000      # per-host port budget

    # WebSocket / progress
    progress_channel_buffer: int = 256

    @field_validator("cors_origins", "target_allowlist", mode="before")
    @classmethod
    def _strip_spaces(cls, v):
        return ",".join(part.strip() for part in str(v).split(",") if part.strip()) if v else v

    @property
    def cors_origin_list(self) -> list[str]:
        return [o for o in self.cors_origins.split(",") if o]

    @property
    def target_allowlist_list(self) -> list[str]:
        return [a for a in self.target_allowlist.split(",") if a]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
