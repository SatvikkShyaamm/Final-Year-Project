"""
services/auth/ -> Module 2: authentication business logic.

Sits between the API layer (app/api/v1/endpoints/auth.py) and the persistence
layer (app/models/user.py). Endpoints do request/response translation and HTTP
status mapping; everything about *how* a user is created or verified lives
here so Module 3's session layer can call `authenticate_user` without going
through HTTP.
"""
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
]
