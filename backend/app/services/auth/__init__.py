"""
services/auth/ -> Module 2: authentication business logic.

Sits between the API layer (app/api/v1/endpoints/auth.py) and the persistence
layer (app/models/user.py). Endpoints do request/response translation and HTTP
status mapping; everything about *how* a user is created or verified lives
here so Module 3's session layer can call `authenticate_user` without going
through HTTP.

  revocation.py  server-side access-token denylist (Redis, keyed by `jti`),
                 consulted by get_current_user / resolve_ws_user
  wiring.py      registers the token-revocation reaction on the session_closed
                 hook — same pattern as Module 4's ACL / Module 5's trust score

Importing this package wires the session hook (via wiring.py), so a session
ending anywhere in the app also revokes the token that opened it.
"""
from app.services.auth import wiring as _wiring  # noqa: F401  (registers hook)
from app.services.auth.revocation import is_token_revoked, revoke_access_token
from app.services.auth.service import (
    AuthError,
    DuplicateUserError,
    InvalidCredentialsError,
    authenticate_user,
    get_user_by_id,
    get_user_by_username,
    register_user,
)

__all__ = [
    "AuthError",
    "DuplicateUserError",
    "InvalidCredentialsError",
    "authenticate_user",
    "get_user_by_id",
    "get_user_by_username",
    "register_user",
    "is_token_revoked",
    "revoke_access_token",
]
