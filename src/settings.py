from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", case_sensitive=False, extra="ignore"
    )

    connection_id: int = Field(..., description="Connection ID for API authentication")
    audience: str = Field(
        default="https://api.example.com", description="JWT audience claim"
    )
    token_expiry_minutes: int = Field(
        default=5, description="Token expiry time in minutes"
    )
    key_size: int = Field(default=4096, description="RSA key size in bits")
    certificates_dir: Path = Field(
        default_factory=lambda: Path.cwd() / "certificates",
        description="Directory to store certificates and keys",
    )

    @field_validator("connection_id")
    @classmethod
    def validate_connection_id(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("connection_id must be a positive integer")
        return v

    @field_validator("token_expiry_minutes")
    @classmethod
    def validate_token_expiry(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("token_expiry_minutes must be positive")
        return v

    @field_validator("key_size")
    @classmethod
    def validate_key_size(cls, v: int) -> int:
        if v < 2048:
            raise ValueError("key_size must be at least 2048 bits")
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
