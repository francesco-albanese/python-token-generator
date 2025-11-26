import time

import pytest

from src.crypto import generate_rsa_keypair
from src.exceptions import TokenSigningError, TokenVerificationError
from src.jwt_handler import sign_token, verify_token


def test_sign_token():
    """Test signing a JWT token"""
    public_pem, private_pem = generate_rsa_keypair(2048)
    kid = "test-kid-123"
    connection_id = 12345
    audience = "https://api.example.com"
    expiry_minutes = 5

    token = sign_token(private_pem, kid, connection_id, audience, expiry_minutes)

    assert isinstance(token, str)
    assert len(token) > 0
    parts = token.split(".")
    assert len(parts) == 3


def test_verify_token():
    """Test verifying a JWT token"""
    public_pem, private_pem = generate_rsa_keypair(2048)
    kid = "test-kid-456"
    connection_id = 67890
    audience = "https://api.test.com"
    expiry_minutes = 10

    token = sign_token(private_pem, kid, connection_id, audience, expiry_minutes)
    payload = verify_token(token, public_pem, audience)

    assert payload["sub"] == str(connection_id)
    assert payload["iss"] == str(connection_id)
    assert payload["aud"] == audience
    assert "jti" in payload
    assert "exp" in payload
    assert "iat" in payload


def test_verify_token_validates_expiry():
    """Test token expiry validation"""
    public_pem, private_pem = generate_rsa_keypair(2048)
    kid = "test-kid-789"
    connection_id = 999
    audience = "https://api.example.com"

    current_time = int(time.time())
    payload_dict = {
        "aud": audience,
        "exp": current_time - 100,
        "iat": current_time - 200,
        "iss": str(connection_id),
        "sub": str(connection_id),
        "jti": "test-jti",
    }

    from jose import jwt

    token = jwt.encode(
        payload_dict,
        private_pem,
        algorithm="RS256",
        headers={"alg": "RS256", "kid": kid},
    )

    with pytest.raises(TokenVerificationError) as exc_info:
        verify_token(token, public_pem, audience)
    assert "expired" in str(exc_info.value).lower()


def test_verify_token_wrong_audience():
    """Test token verification fails with wrong audience"""
    public_pem, private_pem = generate_rsa_keypair(2048)
    kid = "test-kid-wrong-aud"
    connection_id = 123
    audience = "https://api.example.com"
    wrong_audience = "https://api.wrong.com"

    token = sign_token(private_pem, kid, connection_id, audience, 5)

    with pytest.raises(TokenVerificationError) as exc_info:
        verify_token(token, public_pem, wrong_audience)
    assert "audience" in str(exc_info.value).lower()


def test_verify_token_wrong_key():
    """Test token verification fails with wrong public key"""
    _, private_pem = generate_rsa_keypair(2048)
    wrong_public_pem, _ = generate_rsa_keypair(2048)

    kid = "test-kid-wrong-key"
    connection_id = 456
    audience = "https://api.example.com"

    token = sign_token(private_pem, kid, connection_id, audience, 5)

    with pytest.raises(TokenVerificationError) as exc_info:
        verify_token(token, wrong_public_pem, audience)
    assert (
        "verify" in str(exc_info.value).lower()
        or "signature" in str(exc_info.value).lower()
    )


def test_verify_token_malformed():
    """Test token verification fails with malformed token"""
    public_pem, _ = generate_rsa_keypair(2048)
    malformed_token = "not.a.valid.jwt.token"

    with pytest.raises(TokenVerificationError):
        verify_token(malformed_token, public_pem, "https://api.example.com")


def test_sign_token_with_invalid_key():
    """Test signing token with invalid key data"""
    invalid_key = b"INVALID KEY DATA"
    kid = "test-kid"
    connection_id = 123
    audience = "https://api.example.com"

    with pytest.raises(TokenSigningError):
        sign_token(invalid_key, kid, connection_id, audience, 5)


def test_token_payload_structure():
    """Test the structure of the decoded token payload"""
    public_pem, private_pem = generate_rsa_keypair(2048)
    kid = "test-kid-structure"
    connection_id = 11111
    audience = "https://api.example.com"
    expiry_minutes = 15

    token = sign_token(private_pem, kid, connection_id, audience, expiry_minutes)
    payload = verify_token(token, public_pem, audience)

    required_fields = ["sub", "aud", "exp", "iat", "iss", "jti"]
    for field in required_fields:
        assert field in payload

    assert isinstance(payload["exp"], int)
    assert isinstance(payload["iat"], int)
    assert payload["exp"] > payload["iat"]
