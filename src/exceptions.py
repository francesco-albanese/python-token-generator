class TokenGeneratorError(Exception):
    """Base exception for token generator"""


class KeyNotFoundError(TokenGeneratorError):
    """Raised when RSA keys are not found"""


class KeyGenerationError(TokenGeneratorError):
    """Raised when RSA key generation fails"""


class TokenSigningError(TokenGeneratorError):
    """Raised when JWT signing fails"""


class TokenVerificationError(TokenGeneratorError):
    """Raised when JWT verification fails"""


class SettingsError(TokenGeneratorError):
    """Raised when settings validation fails"""
