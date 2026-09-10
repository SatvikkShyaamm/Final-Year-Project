"""
Pydantic request/response schemas for Module 2 — Authentication.

Kept separate from the ORM model (app/models/user.py) so the wire contract
the frontend depends on doesn't move every time the DB schema does. The
frontend mirrors these in frontend/src/types/index.ts.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.schemas.mfa import MFAChallengeOut

# bcrypt hashes at most the first 72 *bytes* of a password. We reject anything
# longer outright rather than silently truncating it (a silent truncation would
# make "correct horse battery staple ..." and a different 73rd byte log in with
# the same hash). 8 is a deliberately modest floor for a demo system — Module 10
# can revisit policy.
_PASSWORD_MIN = 8
_PASSWORD_MAX = 72

_USERNAME_PATTERN = r"^[A-Za-z0-9_.-]+$"


def _check_password_bytes(value: str) -> str:
    if len(value.encode("utf-8")) > _PASSWORD_MAX:
        raise ValueError(f"password must be at most {_PASSWORD_MAX} bytes")
    return value


class UserCreate(BaseModel):
    """Body of POST /auth/register."""

    username: str = Field(
        min_length=3, max_length=50, pattern=_USERNAME_PATTERN,
        examples=["alice"],
    )
    email: EmailStr = Field(examples=["alice@example.com"])
    password: str = Field(min_length=_PASSWORD_MIN, max_length=_PASSWORD_MAX)

    _password_bytes = field_validator("password")(_check_password_bytes)


class LoginRequest(BaseModel):
    """JSON body of POST /auth/login."""

    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=_PASSWORD_MAX)

    _password_bytes = field_validator("password")(_check_password_bytes)


class UserRead(BaseModel):
    """Public representation of a user — never includes the password hash."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None


class Token(BaseModel):
    """Response of POST /auth/login and POST /auth/register.

    `access_token` + `token_type` follow the OAuth2 bearer convention so the
    frontend axios interceptor can treat it generically. `user` is bundled in
    so the client doesn't need an immediate follow-up call to /auth/me.
    """

    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Access token lifetime in seconds")
    user: UserRead


class TokenPayload(BaseModel):
    """Decoded JWT claims we care about. Not used by Module 2 itself (the auth
    dep reads the dict directly) but documents the contract Module 3's
    WebSocket handshake will validate against."""

    sub: str
    type: str
    exp: int
    iat: int


class LoginResponse(BaseModel):
    """Response of POST /auth/login (Module 6 turns login into a risk decision).

    `mfa_required` is the discriminator:
      - false -> `access_token` + `user` are present (risk band LOW, or MFA
        disabled); use them exactly like a Module 2 token.
      - true  -> `mfa` is present; complete it at POST /mfa/verify, which
        returns a normal `Token`.
    A HIGH-risk login does not reach this model at all — it is HTTP 403.
    """

    mfa_required: bool
    decision: str                      # "allow" | "mfa"
    trust_score: int | None = None
    risk_level: str | None = None

    # present iff mfa_required is False
    access_token: str | None = None
    token_type: str | None = None
    expires_in: int | None = None
    user: UserRead | None = None

    # present iff mfa_required is True
    mfa: MFAChallengeOut | None = None
