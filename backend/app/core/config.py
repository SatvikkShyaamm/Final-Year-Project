"""
Centralized application configuration.

All settings are loaded from environment variables (see /.env.example and
/backend/.env.example). Nothing here should be hard-coded for production —
this module exists precisely so that Module 5/6/7 thresholds, JWT secrets,
and infrastructure hosts can be tuned without touching code.
"""
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---- General ----
    project_name: str = "ZTSAACM Security Dashboard"
    environment: str = "development"

    # ---- PostgreSQL ----
    postgres_user: str = "ztsaacm"
    postgres_password: str = "change_me_dev_password"
    postgres_db: str = "ztsaacm_db"
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    # ---- Redis ----
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str | None = None

    # ---- Backend ----
    backend_port: int = 8000
    jwt_secret_key: str = "change_me_dev_secret_key"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # ---- Session lifecycle (Module 3) ----
    # An application session ends when its WebSocket closes; these bound how
    # long an *idle* or *very old* session may linger if the socket somehow
    # stays half-open. All tunable for Module 10's evaluation.
    session_idle_timeout_minutes: int = 30
    session_max_lifetime_minutes: int = 480
    session_sweep_interval_seconds: int = 30
    session_ws_heartbeat_seconds: int = 20

    # ---- Dynamic ACL (Module 4) ----
    # Which enforcement backend the L-PEP worker uses:
    #   auto      - use real ipset if the `ipset` command works, else simulate
    #   ipset     - always shell out to ipset/ip6tables (needs a Linux host +
    #               NET_ADMIN; this is what the standalone infra/l-pep runs)
    #   simulated - record the kernel allow-list in Redis only (dev / Docker / CI)
    acl_enforcement_backend: str = "auto"
    # Label for what the allow-list entry grants reach to (the paper's
    # "protected resource" behind the enforcement point).
    acl_protected_resource: str = "protected-app"
    # ipset set names, matching the base paper's ztsaacm_allowed / _v6.
    acl_ipset_v4: str = "ztsaacm_allowed"
    acl_ipset_v6: str = "ztsaacm_allowed_v6"
    # Fail-safe TTL (seconds) on each kernel allow-list entry so a lost
    # revocation can't leave access open forever. 0 disables it.
    acl_entry_ttl_seconds: int = 900
    # Run the L-PEP task consumer inside this process (single-container dev /
    # demo). Set false when running the standalone infra/l-pep worker instead.
    l_pep_worker_enabled: bool = True
    l_pep_poll_timeout_seconds: int = 1

    # Kept as a raw comma-separated string (not List[str]) because
    # pydantic-settings tries to JSON-decode list-typed env vars before any
    # validator runs, which breaks on a plain "http://a,http://b" value.
    # Use the `cors_origins` property below to get the parsed list.
    cors_origins_raw: str = Field(default="http://localhost:5173", validation_alias="CORS_ORIGINS")

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins_raw.split(",") if origin.strip()]

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/0"


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor — import and call this, don't instantiate directly."""
    return Settings()
