import pytest
from typer.testing import CliRunner

from src.cli import app
from src.crypto import generate_kid, generate_rsa_keypair, save_kid, store_pems_to_files

runner = CliRunner()


@pytest.fixture
def mock_settings(monkeypatch):
    """Mock settings for CLI tests"""
    monkeypatch.setenv("CONNECTION_ID", "12345")
    from src.settings import get_settings

    get_settings.cache_clear()
    return get_settings()


def test_cli_generates_keys_when_none_exist(tmp_path, mock_settings, monkeypatch):
    """Test CLI generates keys when none exist"""
    monkeypatch.setenv("CONNECTION_ID", "12345")
    monkeypatch.setenv("CERTIFICATES_DIR", str(tmp_path))

    from src.settings import get_settings

    get_settings.cache_clear()

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert (tmp_path / "public_key.pem").exists()
    assert (tmp_path / "private_key.pem").exists()
    assert (tmp_path / "kid.txt").exists()
    assert (tmp_path / "jwks.json").exists()


def test_cli_uses_existing_keys(tmp_path, mock_settings, monkeypatch):
    """Test CLI uses existing keys if present"""
    monkeypatch.setenv("CONNECTION_ID", "12345")
    monkeypatch.setenv("CERTIFICATES_DIR", str(tmp_path))

    from src.settings import get_settings

    get_settings.cache_clear()

    public_pem, private_pem = generate_rsa_keypair(2048)
    test_kid = generate_kid()
    store_pems_to_files(public_pem, private_pem, tmp_path)
    save_kid(test_kid, tmp_path)

    kid_before = (tmp_path / "kid.txt").read_text()

    result = runner.invoke(app, [])

    assert result.exit_code == 0
    kid_after = (tmp_path / "kid.txt").read_text()
    assert kid_before == kid_after


def test_cli_force_flag_regenerates_keys(tmp_path, mock_settings, monkeypatch):
    """Test CLI --force flag regenerates keys"""
    monkeypatch.setenv("CONNECTION_ID", "12345")
    monkeypatch.setenv("CERTIFICATES_DIR", str(tmp_path))

    from src.settings import get_settings

    get_settings.cache_clear()

    public_pem, private_pem = generate_rsa_keypair(2048)
    test_kid = generate_kid()
    store_pems_to_files(public_pem, private_pem, tmp_path)
    save_kid(test_kid, tmp_path)

    kid_before = (tmp_path / "kid.txt").read_text()

    result = runner.invoke(app, ["--force"])

    assert result.exit_code == 0
    kid_after = (tmp_path / "kid.txt").read_text()
    assert kid_before != kid_after


def test_cli_load_only_flag_uses_existing(tmp_path, mock_settings, monkeypatch):
    """Test CLI --load-only flag only loads existing keys"""
    monkeypatch.setenv("CONNECTION_ID", "12345")
    monkeypatch.setenv("CERTIFICATES_DIR", str(tmp_path))

    from src.settings import get_settings

    get_settings.cache_clear()

    public_pem, private_pem = generate_rsa_keypair(2048)
    test_kid = generate_kid()
    store_pems_to_files(public_pem, private_pem, tmp_path)
    save_kid(test_kid, tmp_path)

    result = runner.invoke(app, ["--load-only"])

    assert result.exit_code == 0


def test_cli_load_only_fails_without_keys(tmp_path, mock_settings, monkeypatch):
    """Test CLI --load-only fails when no keys exist"""
    monkeypatch.setenv("CONNECTION_ID", "12345")
    monkeypatch.setenv("CERTIFICATES_DIR", str(tmp_path))

    from src.settings import get_settings

    get_settings.cache_clear()

    result = runner.invoke(app, ["--load-only"])

    assert result.exit_code == 1


def test_cli_force_and_load_only_conflict(mock_settings, monkeypatch):
    """Test CLI fails with both --force and --load-only"""
    monkeypatch.setenv("CONNECTION_ID", "12345")

    from src.settings import get_settings

    get_settings.cache_clear()

    result = runner.invoke(app, ["--force", "--load-only"])

    assert result.exit_code == 1


def test_cli_output_dir_override(tmp_path, mock_settings, monkeypatch):
    """Test CLI --output-dir overrides settings"""
    monkeypatch.setenv("CONNECTION_ID", "12345")

    from src.settings import get_settings

    get_settings.cache_clear()

    custom_dir = tmp_path / "custom"
    result = runner.invoke(app, ["--output-dir", str(custom_dir)])

    assert result.exit_code == 0
    assert (custom_dir / "public_key.pem").exists()
    assert (custom_dir / "private_key.pem").exists()
    assert (custom_dir / "kid.txt").exists()


def test_cli_missing_connection_id(monkeypatch, tmp_path):
    """Test CLI fails without CONNECTION_ID"""
    monkeypatch.delenv("CONNECTION_ID", raising=False)
    monkeypatch.chdir(tmp_path)

    from src.settings import get_settings

    get_settings.cache_clear()

    result = runner.invoke(app, [])

    assert result.exit_code == 1


def test_cli_invalid_settings(monkeypatch):
    """Test CLI fails with invalid settings"""
    monkeypatch.setenv("CONNECTION_ID", "0")

    from src.settings import get_settings

    get_settings.cache_clear()

    result = runner.invoke(app, [])

    assert result.exit_code == 1
