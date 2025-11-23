import sys

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .logger import logger


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", case_sensitive=False, extra="ignore"
    )

    connection_id: int = Field(..., description="Connection ID for API authentication")

    @field_validator("connection_id")
    @classmethod
    def validate_connection_id(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("connection_id must be a positive integer")
        return v


def load_settings() -> Settings:
    try:
        return Settings()
    except Exception as e:
        logger.error(
            "Failed to load settings",
            extra={"error": str(e), "hint": "Copy .env.example to .env and set CONNECTION_ID"},
        )
        sys.exit(1)


SETTINGS = load_settings()
