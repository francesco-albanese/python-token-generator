import json
from pathlib import Path

import pytest

from src.crypto import (
    convert_public_key_to_jwk,
    generate_kid,
    generate_rsa_keypair,
    keys_exist,
    load_kid,
    load_pems_from_files,
    save_kid,
    store_pems_to_files,
)
from src.exceptions import KeyNotFoundError


def test_generate_kid():
    """Test kid generation produces unique IDs"""
    kid1 = generate_kid()
    kid2 = generate_kid()
    assert kid1 != kid2
    assert len(kid1) > 0
    assert len(kid2) > 0


def test_generate_rsa_keypair():
    """Test RSA keypair generation"""
    public_pem, private_pem = generate_rsa_keypair(2048)

    assert b"BEGIN PUBLIC KEY" in public_pem
    assert b"END PUBLIC KEY" in public_pem
    assert b"BEGIN PRIVATE KEY" in private_pem
    assert b"END PRIVATE KEY" in private_pem


def test_generate_rsa_keypair_different_sizes():
    """Test RSA keypair generation with different key sizes"""
    public_2048, _ = generate_rsa_keypair(2048)
    public_4096, _ = generate_rsa_keypair(4096)

    assert len(public_4096) > len(public_2048)


def test_store_and_load_pems(tmp_path):
    """Test storing and loading PEM files"""
    public_pem, private_pem = generate_rsa_keypair(2048)

    store_pems_to_files(public_pem, private_pem, tmp_path)

    assert (tmp_path / "public_key.pem").exists()
    assert (tmp_path / "private_key.pem").exists()

    loaded_public, loaded_private = load_pems_from_files(tmp_path)
    assert loaded_public == public_pem
    assert loaded_private == private_pem


def test_load_pems_not_found(tmp_path):
    """Test loading PEMs when files don't exist"""
    with pytest.raises(KeyNotFoundError) as exc_info:
        load_pems_from_files(tmp_path)
    assert "not found" in str(exc_info.value).lower()


def test_save_and_load_kid(tmp_path):
    """Test saving and loading kid"""
    test_kid = "test-kid-123"
    save_kid(test_kid, tmp_path)

    assert (tmp_path / "kid.txt").exists()

    loaded_kid = load_kid(tmp_path)
    assert loaded_kid == test_kid


def test_load_kid_not_found(tmp_path):
    """Test loading kid when file doesn't exist"""
    loaded_kid = load_kid(tmp_path)
    assert loaded_kid is None


def test_load_kid_empty_file(tmp_path):
    """Test loading kid from empty file"""
    kid_file = tmp_path / "kid.txt"
    kid_file.write_text("", encoding="utf-8")

    loaded_kid = load_kid(tmp_path)
    assert loaded_kid is None


def test_keys_exist(tmp_path):
    """Test checking if keys exist"""
    assert not keys_exist(tmp_path)

    public_pem, private_pem = generate_rsa_keypair(2048)
    store_pems_to_files(public_pem, private_pem, tmp_path)
    save_kid("test-kid", tmp_path)

    assert keys_exist(tmp_path)


def test_keys_exist_partial_files(tmp_path):
    """Test keys_exist returns False if not all files present"""
    public_pem, _ = generate_rsa_keypair(2048)
    (tmp_path / "public_key.pem").write_bytes(public_pem)

    assert not keys_exist(tmp_path)


def test_convert_public_key_to_jwk(tmp_path):
    """Test converting public key to JWKS format"""
    public_pem, _ = generate_rsa_keypair(2048)
    test_kid = "test-kid-456"

    jwks = convert_public_key_to_jwk(public_pem, test_kid, tmp_path)

    assert "keys" in jwks
    assert len(jwks["keys"]) == 1

    jwk = jwks["keys"][0]
    assert jwk["kid"] == test_kid
    assert jwk["alg"] == "RS256"
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert "e" in jwk
    assert "n" in jwk

    jwks_file = tmp_path / "jwks.json"
    assert jwks_file.exists()

    loaded_jwks = json.loads(jwks_file.read_text(encoding="utf-8"))
    assert loaded_jwks == jwks


def test_convert_public_key_to_jwk_invalid_key():
    """Test converting non-RSA key raises TypeError"""
    # Create invalid PEM data
    invalid_pem = b"INVALID KEY DATA"

    with pytest.raises(Exception):
        convert_public_key_to_jwk(invalid_pem, "test-kid", Path("/tmp"))
