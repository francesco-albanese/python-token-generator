from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", case_sensitive=False, extra="ignore"
    )

    connection_id: int = Field(..., description="Connection ID assigned by Pirum")

    @field_validator("connection_id")
    @classmethod
    def validate_connection_id(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("connection_id must be a positive integer")
        return v


SETTINGS = Settings()  # type: ignore The values are populated from environment variables or .env file
