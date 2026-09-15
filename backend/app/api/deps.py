"""
Shared FastAPI dependencies.

`get_db` is re-exported here (rather than importing app.core.database directly
in every endpoint) so DB access has one import site. Module 2 adds the
authentication dependencies here for the same reason: every protected endpoint
in Modules 3-9 does `user = Depends(get_current_user)` / `Depends(get_current_admin)`
and never re-implements token parsing.
"""
from __future__ import annotations

from contextlib import suppress
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.database import get_db  # noqa: F401  (re-exported)
from app.core.security import TokenError, decode_access_token
from app.models.user import User
from app.services.auth import get_user_by_id
from app.services.auth.revocation import is_token_revoked
from app.services.trust_score import request_rate

# tokenUrl is the login endpoint's path relative to the server root; it only
# affects Swagger's "Authorize" dialog, not runtime behaviour.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)

_CREDENTIALS_EXC = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(
    request: Request,
    token: Annotated[str | None, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """
    Resolve the bearer token to a live, active User row.

    This is the "authentication middleware" deliverable: 401 on a missing,
    malformed, expired, or wrong-type token; 401 if the subject no longer
    exists or has been deactivated; 401 if the token has been server-side
    revoked (its owning session was terminated — see
    app.services.auth.revocation), so a copy of a dead session's token can't
    keep authenticating REST calls after that session has ended.

    2026-09-15 (Module 7 Section 18 request-rate redesign): also feeds the
    request-rate detector (app.services.trust_score.request_rate) — every
    non-GET/HEAD/OPTIONS authenticated call, from ANY endpoint, counts
    towards the caller's own session's abnormal_request_rate window. This
    is deliberately the single choke point nearly every protected endpoint
    already passes through, so no per-endpoint instrumentation is needed.
    Wrapped in `suppress(Exception)` on top of that module's own fail-open
    guarantees, as an extra safety net: this dependency runs on almost
    every request in the app and must never be the reason a request fails.
    """
    if not token:
        raise _CREDENTIALS_EXC

    try:
        payload = decode_access_token(token)
        user_id = int(payload["sub"])
    except (TokenError, KeyError, ValueError):
        raise _CREDENTIALS_EXC

    if is_token_revoked(payload.get("jti")):
        raise _CREDENTIALS_EXC

    user = get_user_by_id(db, user_id)
    if user is None or not user.is_active:
        raise _CREDENTIALS_EXC

    with suppress(Exception):
        request_rate.record_authenticated_call(user.id, request.method)

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_current_admin(user: CurrentUser) -> User:
    """Authorization gate for admin-only surfaces (the SOC dashboard, Module 8).

    Kept separate from `get_current_user` on purpose: authentication ("who are
    you?") and authorization ("what may you do?") are distinct concerns per the
    project's architectural rules.
    """
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return user


CurrentAdmin = Annotated[User, Depends(get_current_admin)]
