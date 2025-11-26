import json
from pathlib import Path

import typer
from pydantic import ValidationError

from .crypto import (
    convert_public_key_to_jwk,
    generate_kid,
    generate_rsa_keypair,
    keys_exist,
    load_kid,
    load_pems_from_files,
    save_kid,
    store_pems_to_files,
)
from .exceptions import KeyNotFoundError, TokenGeneratorError
from .jwt_handler import sign_token, verify_token
from .logger import logger
from .settings import get_settings

app = typer.Typer(add_completion=False)


@app.command()
def main(
    force: bool = typer.Option(
        False, "--force", help="Force regeneration of keys even if they exist"
    ),
    load_only: bool = typer.Option(
        False, "--load-only", help="Only load existing keys, do not generate new ones"
    ),
    output_dir: Path | None = typer.Option(
        None, "--output-dir", help="Override certificates directory from settings"
    ),
) -> None:
    """Generate RSA keypair and JWT token for API authentication"""
    try:
        settings = get_settings()
    except ValidationError as e:
        logger.error(
            "Settings validation failed",
            extra={"error": str(e), "hint": "Check .env file configuration"},
        )
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error("Failed to load settings", extra={"error": str(e)})
        raise typer.Exit(code=1)

    certificates_dir = output_dir if output_dir else settings.certificates_dir

    if load_only and force:
        logger.error("Cannot use --force and --load-only together")
        raise typer.Exit(code=1)

    try:
        if load_only:
            if not keys_exist(certificates_dir):
                raise KeyNotFoundError(
                    f"No keys found in {certificates_dir}. Remove --load-only to generate."
                )

            logger.info("Loading existing keys")
            public_pem, private_pem = load_pems_from_files(certificates_dir)
            kid = load_kid(certificates_dir)

            if not kid:
                raise KeyNotFoundError("kid.txt not found or empty")

        elif force or not keys_exist(certificates_dir):
            if force:
                logger.info("Force flag set, regenerating keys")
            else:
                logger.info("No existing keys found, generating new keys")

            public_pem, private_pem = generate_rsa_keypair(settings.key_size)
            kid = generate_kid()

            store_pems_to_files(public_pem, private_pem, certificates_dir)
            save_kid(kid, certificates_dir)
            jwks = convert_public_key_to_jwk(public_pem, kid, certificates_dir)

            logger.info(f"JWKS: {json.dumps(jwks, indent=2)}")

        else:
            logger.info("Using existing keys")
            public_pem, private_pem = load_pems_from_files(certificates_dir)
            kid = load_kid(certificates_dir)

            if not kid:
                raise KeyNotFoundError("kid.txt not found or empty")

        token = sign_token(
            private_pem=private_pem,
            kid=kid,
            connection_id=settings.connection_id,
            audience=settings.audience,
            expiry_minutes=settings.token_expiry_minutes,
        )

        decoded_payload = verify_token(
            token=token,
            public_pem=public_pem,
            audience=settings.audience,
        )

        logger.info(f"Encoded JWT: {token}")
        logger.info(f"Decoded JWT: {decoded_payload}")

    except TokenGeneratorError as e:
        logger.error(str(e))
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error("Unexpected error", extra={"error": str(e)})
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
