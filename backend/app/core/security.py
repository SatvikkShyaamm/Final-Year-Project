"""
Low-level security primitives for Module 2 — Authentication.

Deliberately split from the auth *business logic* (app/services/auth) and the
auth *API surface* (app/api/v1/endpoints/auth.py): this module only knows how
to hash a password and how to mint/verify a JWT. It has no database or
FastAPI dependency, so Module 3's WebSocket layer (the base paper's SS-PDP
"JWT verification" step) can reuse `decode_access_token` without pulling in
the REST stack.

Password hashing: bcrypt directly (via the `bcrypt` package), not passlib.
For a two-person student project this is the simplest reliable option —
one well-known algorithm, no compatibility shim layer. bcrypt only reads the
first 72 bytes of a password, so the auth schemas cap password length at 72
(see app/schemas/auth.py) rather than silently truncating here.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt

from app.core.config import get_settings

settings = get_settings()

# Marks the token kind in the payload. Module 6 (Adaptive MFA) will add a
# short-lived "mfa_pending" token type alongside this one; keeping the claim
# explicit from the start means that change won't be ambiguous.
ACCESS_TOKEN_TYPE = "access"


# --------------------------------------------------------------------------- #
# Password hashing
# --------------------------------------------------------------------------- #
def hash_password(plain_password: str) -> str:
    """Return a bcrypt hash (including salt) for storage in users.hashed_password."""
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Constant-time check of a candidate password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"), hashed_password.encode("utf-8")
        )
    except (ValueError, TypeError):
        # Malformed/empty hash in the row — treat as a failed match, never raise
        # into the request handler.
        return False


# --------------------------------------------------------------------------- #
# JSON Web Tokens
# --------------------------------------------------------------------------- #
def create_access_token(
    subject: str | int,
    *,
    expires_minutes: int | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """
    Mint a signed access token.

    `subject` is the user id; it lands in the standard `sub` claim as a string.
    `exp`/`iat` are timezone-aware UTC. Thresholds/lifetimes come from settings
    so they stay tunable for Module 10's evaluation without code changes.
    """
    now = datetime.now(timezone.utc)
    expire_minutes = (
        expires_minutes
        if expires_minutes is not None
        else settings.access_token_expire_minutes
    )
    payload: dict[str, Any] = {
        "sub": str(subject),
        "type": ACCESS_TOKEN_TYPE,
        "iat": now,
        "exp": now + timedelta(minutes=expire_minutes),
    }
    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(
        payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
    )


class TokenError(Exception):
    """Raised when a token is missing, malformed, expired, or wrong-typed.

    The API layer maps this to HTTP 401; lower layers can catch it without
    importing FastAPI.
    """


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Verify signature + expiry and return the claims dict.

    Raises `TokenError` on any problem so callers have a single exception type
    to handle regardless of the underlying PyJWT error.
    """
    try:
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired") from exc
    except jwt.PyJWTError as exc:
        raise TokenError("Could not validate token") from exc

    if payload.get("type") != ACCESS_TOKEN_TYPE:
        raise TokenError("Wrong token type")
    if not payload.get("sub"):
        raise TokenError("Token missing subject")

    return payload
