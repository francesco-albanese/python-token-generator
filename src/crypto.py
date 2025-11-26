import json
from pathlib import Path
from typing import TypedDict
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk
from jose.constants import Algorithms

from .exceptions import KeyGenerationError, KeyNotFoundError
from .logger import logger


class JWK(TypedDict):
    kid: str
    alg: str
    kty: str
    e: str
    n: str
    use: str


class JWKS(TypedDict):
    keys: list[JWK]


def generate_kid() -> str:
    """Generate a new key ID"""
    return str(uuid4())


def load_kid(certificates_dir: Path) -> str | None:
    """Load existing kid from kid.txt if it exists"""
    kid_file = certificates_dir / "kid.txt"
    if kid_file.exists():
        kid = kid_file.read_text(encoding="utf-8").strip()
        if kid:
            logger.debug(f"Loaded existing kid from {kid_file}")
            return kid
    return None


def save_kid(kid: str, certificates_dir: Path) -> None:
    """Save kid to kid.txt"""
    kid_file = certificates_dir / "kid.txt"
    kid_file.write_text(kid, encoding="utf-8")
    logger.debug(f"Saved kid to {kid_file}")


def keys_exist(certificates_dir: Path) -> bool:
    """Check if RSA key files already exist"""
    public_key_file = certificates_dir / "public_key.pem"
    private_key_file = certificates_dir / "private_key.pem"
    kid_file = certificates_dir / "kid.txt"

    exists = (
        public_key_file.exists() and private_key_file.exists() and kid_file.exists()
    )

    if exists:
        logger.info(f"Existing keys found in {certificates_dir}")

    return exists


def generate_rsa_keypair(key_size: int) -> tuple[bytes, bytes]:
    """Generate RSA key pair with specified key size"""
    try:
        logger.info(f"Generating RSA keypair with key_size={key_size}")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        logger.info("RSA keypair generated successfully")
        return public_pem, private_pem
    except Exception as e:
        raise KeyGenerationError(f"Failed to generate RSA keypair: {e}")


def store_pems_to_files(
    public_pem: bytes, private_pem: bytes, certificates_dir: Path
) -> None:
    """Store RSA keys to PEM files"""
    certificates_dir.mkdir(parents=True, exist_ok=True)

    public_key_file = certificates_dir / "public_key.pem"
    private_key_file = certificates_dir / "private_key.pem"

    public_key_file.write_bytes(public_pem)
    private_key_file.write_bytes(private_pem)

    logger.info(f"Stored keys to {certificates_dir}")


def load_pems_from_files(certificates_dir: Path) -> tuple[bytes, bytes]:
    """Load RSA keys from PEM files"""
    public_key_file = certificates_dir / "public_key.pem"
    private_key_file = certificates_dir / "private_key.pem"

    if not public_key_file.exists() or not private_key_file.exists():
        raise KeyNotFoundError(
            f"RSA key files not found in {certificates_dir}. "
            "Run without --load-only to generate keys."
        )

    public_pem = public_key_file.read_bytes()
    private_pem = private_key_file.read_bytes()

    logger.info(f"Loaded keys from {certificates_dir}")
    return public_pem, private_pem


def convert_public_key_to_jwk(
    public_pem: bytes, kid: str, certificates_dir: Path
) -> JWKS:
    """Convert public key PEM to JWKS format using python-jose"""
    key = jwk.construct(public_pem, algorithm=Algorithms.RS256)
    jwk_dict = key.to_dict()

    jwk_entry: JWK = {
        "kid": kid,
        "alg": jwk_dict["alg"],
        "kty": jwk_dict["kty"],
        "e": jwk_dict["e"],
        "n": jwk_dict["n"],
        "use": "sig",
    }
    jwks: JWKS = {"keys": [jwk_entry]}

    jwks_file = certificates_dir / "jwks.json"
    jwks_file.write_text(json.dumps(jwks, indent=2), encoding="utf-8")
    logger.info(f"Generated JWKS at {jwks_file}")

    return jwks
