"""
Authentication business logic — Module 2.

Pure functions over a SQLAlchemy Session. No FastAPI imports here on purpose:
this is the layer Module 3 (session lifecycle) and Module 7 (continuous
evaluation) reuse. HTTP concerns stay in app/api/v1/endpoints/auth.py.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.security import hash_password, verify_password
from app.models.user import User, UserRole

logger = get_logger(__name__)

# A real bcrypt hash computed once at import. Used as a stand-in when the
# username is unknown so `authenticate_user` still performs a full-cost bcrypt
# verification and can't be probed for valid usernames by response timing.
_DUMMY_HASH = hash_password("not-a-real-password-timing-equalizer")


class AuthError(Exception):
    """Base class for expected auth failures (mapped to 4xx by the API layer)."""


class DuplicateUserError(AuthError):
    """Username or email already taken."""


class InvalidCredentialsError(AuthError):
    """Wrong username/password, or the account is disabled."""


# --------------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------------- #
def get_user_by_username(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == username))


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(func.lower(User.email) == email.lower()))


def get_user_by_id(db: Session, user_id: int) -> User | None:
    return db.get(User, user_id)


def _user_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User)) or 0


# --------------------------------------------------------------------------- #
# Writes
# --------------------------------------------------------------------------- #
def register_user(
    db: Session, *, username: str, email: str, password: str
) -> User:
    """
    Create a new user with a bcrypt-hashed password.

    Bootstrap rule: the very first account created on a fresh database is made
    an ADMIN, so a freshly deployed system has someone who can reach the admin
    dashboard without a manual DB edit. Every subsequent registration is a
    normal USER; promoting others is an admin action added in a later module.

    Raises DuplicateUserError if the username or email is already in use.
    """
    if get_user_by_username(db, username) is not None:
        raise DuplicateUserError("username already registered")
    if get_user_by_email(db, email) is not None:
        raise DuplicateUserError("email already registered")

    role = UserRole.ADMIN if _user_count(db) == 0 else UserRole.USER

    user = User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        role=role,
    )
    db.add(user)
    try:
        db.commit()
    except Exception:
        db.rollback()
        # Covers the race where two registrations pass the checks above and
        # then collide on the DB unique constraint.
        raise DuplicateUserError("username or email already registered")
    db.refresh(user)

    logger.info("registered user id=%s username=%s role=%s", user.id, user.username, user.role)
    return user


def authenticate_user(db: Session, *, username: str, password: str) -> User:
    """
    Verify credentials and return the User.

    Always runs a bcrypt verification even when the username is unknown, so a
    caller can't distinguish "no such user" from "wrong password" by timing.
    Raises InvalidCredentialsError on any failure (unknown user, bad password,
    or disabled account).
    """
    user = get_user_by_username(db, username)

    candidate_hash = user.hashed_password if user is not None else _DUMMY_HASH

    password_ok = verify_password(password, candidate_hash)

    if user is None or not password_ok:
        raise InvalidCredentialsError("incorrect username or password")
    if not user.is_active:
        raise InvalidCredentialsError("account is disabled")

    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)

    logger.info("authenticated user id=%s username=%s", user.id, user.username)
    return user
