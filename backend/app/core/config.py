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
