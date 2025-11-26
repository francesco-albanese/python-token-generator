from pathlib import Path

import pytest
from pydantic import ValidationError

from src.settings import Settings, get_settings


def test_settings_with_valid_connection_id(monkeypatch):
    """Test settings with valid connection ID"""
    monkeypatch.setenv("CONNECTION_ID", "12345")
    settings = Settings()
    assert settings.connection_id == 12345
    assert settings.audience == "https://api.example.com"
    assert settings.token_expiry_minutes == 5
    assert settings.key_size == 4096


def test_settings_with_custom_values(monkeypatch):
    """Test settings with custom values"""
    monkeypatch.setenv("CONNECTION_ID", "999")
    monkeypatch.setenv("AUDIENCE", "https://custom.api.com")
    monkeypatch.setenv("TOKEN_EXPIRY_MINUTES", "10")
    monkeypatch.setenv("KEY_SIZE", "2048")
    monkeypatch.setenv("CERTIFICATES_DIR", "/custom/path")

    settings = Settings()
    assert settings.connection_id == 999
    assert settings.audience == "https://custom.api.com"
    assert settings.token_expiry_minutes == 10
    assert settings.key_size == 2048
    assert settings.certificates_dir == Path("/custom/path")


def test_settings_missing_connection_id(monkeypatch):
    """Test settings fails without connection ID"""
    monkeypatch.delenv("CONNECTION_ID", raising=False)
    with pytest.raises(ValidationError) as exc_info:
        Settings(_env_file=None)
    assert "connection_id" in str(exc_info.value).lower()


def test_settings_invalid_connection_id(monkeypatch):
    """Test settings fails with invalid connection ID"""
    monkeypatch.setenv("CONNECTION_ID", "0")
    with pytest.raises(ValidationError) as exc_info:
        Settings()
    assert "positive integer" in str(exc_info.value).lower()


def test_settings_invalid_token_expiry(monkeypatch):
    """Test settings fails with invalid token expiry"""
    monkeypatch.setenv("CONNECTION_ID", "123")
    monkeypatch.setenv("TOKEN_EXPIRY_MINUTES", "-5")
    with pytest.raises(ValidationError) as exc_info:
        Settings()
    assert "positive" in str(exc_info.value).lower()


def test_settings_invalid_key_size(monkeypatch):
    """Test settings fails with invalid key size"""
    monkeypatch.setenv("CONNECTION_ID", "123")
    monkeypatch.setenv("KEY_SIZE", "1024")
    with pytest.raises(ValidationError) as exc_info:
        Settings()
    assert "2048" in str(exc_info.value).lower()


def test_get_settings_cached(monkeypatch):
    """Test settings caching with lru_cache"""
    monkeypatch.setenv("CONNECTION_ID", "123")
    get_settings.cache_clear()

    settings1 = get_settings()
    settings2 = get_settings()

    assert settings1 is settings2
