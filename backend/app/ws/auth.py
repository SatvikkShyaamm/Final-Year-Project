"""
WebSocket handshake authentication — Module 3, hardened for token revocation.

The browser WebSocket API can't set an ``Authorization`` header, so the
signalling socket carries the Module 2 access token as a ``?token=`` query
parameter instead. This reuses the exact same JWT verification the REST
``get_current_user`` dependency uses (base paper: the SS-PDP's "JWT
verification" step) — it just can't be a FastAPI ``Depends`` because there is
no header to read.

Also checks the token against the server-side revocation denylist (see
app.services.auth.revocation) so a token whose session was already terminated
can't be reused to open a brand-new one, and returns the token's `jti` / `exp`
so the caller can stamp them onto the new session row (letting *that*
session's termination revoke this exact token in turn).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.security import TokenError, decode_access_token, token_expiry_datetime
from app.models.user import User
from app.services.auth import get_user_by_id
from app.services.auth.revocation import is_token_revoked


class WsAuthError(Exception):
    """Token missing / invalid / expired / revoked, or the user is gone or disabled."""


@dataclass(frozen=True)
class ResolvedWsAuth:
    user: User
    token_jti: str | None
    token_exp: datetime | None


def resolve_ws_user(token: str | None, db: Session) -> ResolvedWsAuth:
    if not token:
        raise WsAuthError("missing token")
    try:
        payload = decode_access_token(token)
        user_id = int(payload["sub"])
    except (TokenError, KeyError, ValueError) as exc:
        raise WsAuthError("invalid token") from exc

    jti = payload.get("jti")
    if is_token_revoked(jti):
        raise WsAuthError("token revoked")

    user = get_user_by_id(db, user_id)
    if user is None or not user.is_active:
        raise WsAuthError("unknown or disabled user")

    return ResolvedWsAuth(user=user, token_jti=jti, token_exp=token_expiry_datetime(payload))
