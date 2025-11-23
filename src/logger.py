import logging
import sys
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict
from pythonjsonlogger.json import JsonFormatter

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class LoggerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    log_level: LogLevel = "INFO"


def setup_logger(name: str = "token-generator") -> logging.Logger:
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    settings = LoggerSettings()
    logger.setLevel(getattr(logging, settings.log_level))
    logger.propagate = False

    handler = logging.StreamHandler(sys.stderr)
    formatter = JsonFormatter(
        static_fields={"service": "token-generator"},
        timestamp=True,
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


logger = setup_logger()
