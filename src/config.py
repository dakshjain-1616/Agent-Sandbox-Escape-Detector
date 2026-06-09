"""Application configuration via pydantic-settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    OPENROUTER_API_KEY: str = ""
    DEFAULT_TIMEOUT: int = 30
    DEFAULT_MODEL: str = "anthropic/claude-opus-4.8"
    JUDGE_MAX_TOKENS: int = 1024
    APP_VERSION: str = "1.0.0"
    MAX_CONCURRENT_PROBES: int = 6


settings = Settings()