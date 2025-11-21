from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization
from jose import jwt
import json
from pathlib import Path
from time import time
from typing import TypedDict
from uuid import uuid4
import base64
from .settings import SETTINGS


class JWK(TypedDict):
    kid: str
    alg: str
    kty: str
    e: str
    n: str
    use: str


class JWKS(TypedDict):
    keys: list[JWK]

  
class JWTPayload(TypedDict):
    sub: str
    aud: str
    exp: int
    iat: int
    iss: str
    jti: str


certificates_dir = Path(__file__).parent / "certificates"
kid = str(uuid4())

def store_pems_to_files(public_pem: bytes, private_pem: bytes) -> None:
    certificates_dir.mkdir(exist_ok=True)
    with open(certificates_dir / "public_key.pem", "wb") as pub_file:
        pub_file.write(public_pem)
    with open(certificates_dir / "private_key.pem", "wb") as priv_file:
        priv_file.write(private_pem)

def convert_public_key_to_jwk(public_pem: bytes) -> None:
    public_key = serialization.load_pem_public_key(public_pem)
    if not isinstance(public_key, RSAPublicKey):
        raise TypeError("Expected RSA public key")
    numbers = public_key.public_numbers()
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')

    # Base64url encoding without padding
    e_b64 = base64.urlsafe_b64encode(e).decode('utf-8').rstrip('=')
    n_b64 = base64.urlsafe_b64encode(n).decode('utf-8').rstrip('=')

    jwk: JWK = {
        "kid": kid,
        "alg": "RS256",
        "kty": "RSA",
        "e": e_b64,
        "n": n_b64,
        "use": "sig"
    }
    jwks: JWKS = {
        "keys": [jwk]
    }
    print(f"JWKS: {json.dumps(jwks, indent=2)}")
    jwks_file = certificates_dir / "jwks.json"
    jwks_file.write_text(json.dumps(jwks, indent=2), encoding='utf-8')

def generate_rsa_keypair() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_pem, private_pem

def sign_token_with_private_key(private_pem: bytes, public_pem: bytes) -> tuple[str, JWTPayload]:
    current_time = int(time())
    connection_id = str(SETTINGS.connection_id)
    # Create JWT
    payload_dict: dict[str, str | int] = {
        "aud": "https://api.uat.pirumconnect.com",
        "exp": current_time + 5 * 60, # Token valid for 5 minutes
        "iat": current_time,
        "iss": connection_id,
        "sub": connection_id,
        "jti": str(uuid4()),
    }
    protected_headers = {"alg": "RS256", "kid": kid}
    token: str = jwt.encode(
        payload_dict,
        private_pem,
        algorithm="RS256",
        headers=protected_headers
    )
    # Decode and verify
    decoded: dict[str, str | int] = jwt.decode(
        token,
        public_pem,
        algorithms=["RS256"],
        audience="https://api.uat.pirumconnect.com"
    )
    decoded_payload: JWTPayload = {
        "sub": str(decoded["sub"]),
        "aud": str(decoded["aud"]),
        "exp": int(decoded["exp"]),
        "iat": int(decoded["iat"]),
        "iss": str(decoded["iss"]),
        "jti": str(decoded["jti"])
      }
    return token, decoded_payload

def main() -> None:
    public_key_pem, private_key_pem = generate_rsa_keypair()
    store_pems_to_files(public_key_pem, private_key_pem)
    convert_public_key_to_jwk(public_key_pem)
    token, decoded_payload = sign_token_with_private_key(private_key_pem, public_key_pem)
    print(f"Encoded JWT: {token}")
    print(f"Decoded JWT: {decoded_payload}")

if __name__ == "__main__":
    main()
