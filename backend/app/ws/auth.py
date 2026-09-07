"""
WebSocket handshake authentication — Module 3.

The browser WebSocket API can't set an ``Authorization`` header, so the
signalling socket carries the Module 2 access token as a ``?token=`` query
parameter instead. This reuses the exact same JWT verification the REST
``get_current_user`` dependency uses (base paper: the SS-PDP's "JWT
verification" step) — it just can't be a FastAPI ``Depends`` because there is
no header to read.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.security import TokenError, decode_access_token
from app.models.user import User
from app.services.auth import get_user_by_id


class WsAuthError(Exception):
    """Token missing / invalid / expired, or the user is gone or disabled."""


def resolve_ws_user(token: str | None, db: Session) -> User:
    if not token:
        raise WsAuthError("missing token")
    try:
        payload = decode_access_token(token)
        user_id = int(payload["sub"])
    except (TokenError, KeyError, ValueError) as exc:
        raise WsAuthError("invalid token") from exc

    user = get_user_by_id(db, user_id)
    if user is None or not user.is_active:
        raise WsAuthError("unknown or disabled user")
    return user
