import hashlib
import hmac
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Union
from jose import jwt
from app.core.config import settings

logger = logging.getLogger("threatlens.security")

ALGORITHM = "HS256"


# -------------------------------------------------------------------------
# NATIVE CRYPTO PRIMITIVES (OWASP & PRODUCTION-READY CONFORMANCE)
# -------------------------------------------------------------------------
def get_password_hash(password: str) -> str:
    """
    Transforms plain text credentials into deterministic, secure crypto footprints
    using native scrypt key derivation. Completely bypasses legacy passlib backend limitations.
    """
    # Generate a cryptographically secure unique 16-byte salt per account profile
    salt = os.urandom(16)

    # Derivate the secure hash value matching enterprise complexity controls
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=16384,  # CPU/Memory cost parameter
        r=8,  # Block size parameter
        p=1,  # Parallelization parameter
    )

    # Store both the salt and key in a clean, unified hex string format inside the database
    return f"scrypt${salt.hex()}${dk.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Validates plain text input variables against scrypt-derived storage records.
    """
    try:
        if not hashed_password or not hashed_password.startswith("scrypt$"):
            return False

        # Extract operational parameters out of the modular database format string
        _, salt_hex, key_hex = hashed_password.split("$")
        salt = bytes.fromhex(salt_hex)
        recorded_key = bytes.fromhex(key_hex)

        # Run identical scrypt key derivation cycles against the input credentials
        new_key = hashlib.scrypt(
            plain_password.encode("utf-8"), salt=salt, n=16384, r=8, p=1
        )

        # Compare strings securely using constant-time verification checks to prevent timing attacks
        return hmac.compare_digest(new_key, recorded_key)

    except Exception as exc:
        logger.error(
            f"Crypto validation failure during scrypt profile verification: {str(exc)}"
        )
        return False


# -------------------------------------------------------------------------
# STATELESS ACCESS TOKEN LIFE-CYCLE GENERATION
# -------------------------------------------------------------------------
def create_access_token(
    data: dict, expires_delta: Union[timedelta, None] = None
) -> str:
    """Generates a secure, cryptographically signed JSON Web Token (JWT)."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update(
        {
            "exp": expire,
            "iss": "ThreatLens-Core-Gateway",
            "iat": datetime.now(timezone.utc),
        }
    )

    try:
        return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)
    except Exception as exc:
        logger.error(f"Token generation loop breakdown encountered: {str(exc)}")
        raise RuntimeError("Failed to compute system token access signatures.")
