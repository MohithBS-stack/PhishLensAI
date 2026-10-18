"""Security utilities: Argon2id password hashing, JWTs, and token management."""
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Any, Dict, Optional, Union
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
import jwt

from app.core.config import settings

# Argon2id password hasher with RFC 9106 recommended parameters
# memory_cost=64MB (65536 KiB), time_cost=3 iterations, parallelism=4 threads
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

# Pre-computed dummy hash to mitigate side-channel timing attacks when user is not found
_DUMMY_ARGON2_HASH = _hasher.hash("phishlens-dummy-timing-mitigation-password")


def hash_password(password: str) -> str:
    """Hashes a password using Argon2id. Never stores plaintext."""
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against an Argon2id hash."""
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        return False


def verify_dummy_password() -> None:
    """Runs a dummy Argon2 verification to neutralize timing discrepancies on invalid user emails."""
    try:
        _hasher.verify(_DUMMY_ARGON2_HASH, "wrong-password")
    except Exception:
        pass


def generate_secure_token(nbytes: int = 32) -> str:
    """Generates a cryptographically strong random token."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """Computes a SHA-256 digest of a token for secure database storage.
    Raw refresh tokens are never stored in the database.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(
    user_id: Union[str, uuid.UUID],
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Encodes a short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode: Dict[str, Any] = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "type": "access",
    }
    if extra_claims:
        to_encode.update(extra_claims)

    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decodes and validates a JWT access token."""
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["exp", "sub", "iat"]},
    )
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("Token type is not access")
    return payload
