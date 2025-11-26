from time import time
from typing import TypedDict
from uuid import uuid4

from jose import JWTError, jwt

from .exceptions import TokenSigningError, TokenVerificationError
from .logger import logger


class JWTPayload(TypedDict):
    sub: str
    aud: str
    exp: int
    iat: int
    iss: str
    jti: str


def sign_token(
    private_pem: bytes,
    kid: str,
    connection_id: int,
    audience: str,
    expiry_minutes: int,
) -> str:
    """Sign a JWT token with the private key"""
    try:
        current_time = int(time())
        connection_id_str = str(connection_id)

        payload_dict: dict[str, str | int] = {
            "aud": audience,
            "exp": current_time + expiry_minutes * 60,
            "iat": current_time,
            "iss": connection_id_str,
            "sub": connection_id_str,
            "jti": str(uuid4()),
        }

        protected_headers = {"alg": "RS256", "kid": kid}

        token: str = jwt.encode(
            payload_dict, private_pem, algorithm="RS256", headers=protected_headers
        )

        logger.info("JWT token signed successfully")
        return token
    except Exception as e:
        raise TokenSigningError(f"Failed to sign JWT token: {e}")


def verify_token(token: str, public_pem: bytes, audience: str) -> JWTPayload:
    """Verify a JWT token with the public key"""
    try:
        decoded: dict[str, str | int] = jwt.decode(
            token, public_pem, algorithms=["RS256"], audience=audience
        )

        decoded_payload: JWTPayload = {
            "sub": str(decoded["sub"]),
            "aud": str(decoded["aud"]),
            "exp": int(decoded["exp"]),
            "iat": int(decoded["iat"]),
            "iss": str(decoded["iss"]),
            "jti": str(decoded["jti"]),
        }

        logger.info("JWT token verified successfully")
        return decoded_payload
    except JWTError as e:
        raise TokenVerificationError(f"Failed to verify JWT token: {e}")
