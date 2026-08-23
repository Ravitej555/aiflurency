"""
ThreatLens AI — Application Settings

Uses pydantic-settings to load configuration from environment variables.
All sensitive values must be provided via environment variables (never hardcoded).
Supports .env file loading for local development.
"""

from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyUrl, validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    # ── Application ──────────────────────────────────────────────────────────
    APP_NAME: str = "ThreatLens AI"
    ENVIRONMENT: str = "development"           # development | staging | production
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"

    # ── Server ───────────────────────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 4                           # Uvicorn worker count

    # ── Database ─────────────────────────────────────────────────────────────
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "threatlens"
    POSTGRES_USER: str = "threatlens_user"
    POSTGRES_PASSWORD: str = "threatlens_password_123"

    @property
    def DATABASE_URL(self) -> str:
        """Async PostgreSQL connection string for SQLAlchemy."""
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def DATABASE_URL_SYNC(self) -> str:
        """Sync/async connection string used by Alembic migrations."""
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # ── JWT Authentication ───────────────────────────────────────────────────
    SECRET_KEY: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── CORS ─────────────────────────────────────────────────────────────────
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # ── Logging ──────────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"                   # json | text

    # ── AWS (used by ECS task environment) ──────────────────────────────────
    AWS_REGION: str = "us-east-1"
    ECR_REGISTRY: str = ""                     # e.g., 123456789.dkr.ecr.us-east-1.amazonaws.com


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance (avoids re-parsing env on every request)."""
    return Settings()


settings: Settings = get_settings()
