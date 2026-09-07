"""
Module 2 — Authentication endpoints.

Scope (per the Master Project Context, Module 2): user registration, login
issuing a JWT, JWT validation, and an authenticated "who am I" endpoint.
This module answers only "who are you?". Session lifecycle (Module 3),
trust scoring (Module 5) and MFA (Module 6) are separate and layer on top of
the `get_current_user` dependency this module makes available.

    POST /auth/register  -> create account, return JWT + user
    POST /auth/login     -> verify credentials, return JWT + user
    GET  /auth/me        -> current user (requires Bearer token)
    POST /auth/logout    -> client-side token disposal (stateless JWT)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, get_db
from app.core.config import get_settings
from app.core.security import create_access_token
from app.models.session import TerminationReason
from app.schemas.auth import LoginRequest, Token, UserCreate, UserRead
from app.services import session as session_service
from app.services.auth import (
    DuplicateUserError,
    InvalidCredentialsError,
    authenticate_user,
    register_user,
)
from app.ws.connection_manager import manager

router = APIRouter()
settings = get_settings()


def _issue_token(user) -> Token:
    access_token = create_access_token(user.id)
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserRead.model_validate(user),
    )


@router.post(
    "/auth/register",
    tags=["auth"],
    response_model=Token,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user and return an access token",
)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> Token:
    try:
        user = register_user(
            db,
            username=payload.username,
            email=str(payload.email),
            password=payload.password,
        )
    except DuplicateUserError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    return _issue_token(user)


@router.post(
    "/auth/login",
    tags=["auth"],
    response_model=Token,
    summary="Verify credentials and return an access token",
)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> Token:
    try:
        user = authenticate_user(
            db, username=payload.username, password=payload.password
        )
    except InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _issue_token(user)


@router.get(
    "/auth/me",
    tags=["auth"],
    response_model=UserRead,
    summary="Return the currently authenticated user",
)
def read_me(current_user: CurrentUser) -> UserRead:
    return UserRead.model_validate(current_user)


@router.post(
    "/auth/logout",
    tags=["auth"],
    summary="Log out — terminate the user's active session(s)",
)
async def logout(current_user: CurrentUser, db: Session = Depends(get_db)) -> dict:
    """
    The access token itself is stateless (the client discards it), but from
    Module 3 on "logout" also means "end the application session": this walks
    the FSM S2 -> S3 for every active session the user holds and closes the
    signalling socket. This is the deliberate cross-module call the deliverable
    "Logout -> WebSocket Closed -> Session Terminated" requires.
    """
    terminated = session_service.terminate_user_sessions(
        db, current_user.id, reason=TerminationReason.LOGOUT
    )
    for session_id in terminated:
        # Send session.terminated before the close frame -- see the comment on
        # ConnectionManager.close() for why the order matters. The frontend
        # normally tears its own socket down on logout anyway, but this closes
        # the same race window admin-terminate had if that teardown is ever
        # delayed relative to this server-side close.
        await manager.close(
            session_id,
            code=1000,
            reason="logout",
            message={"type": "session.terminated", "reason": "logout"},
        )
    return {
        "detail": "Logged out. Discard the access token on the client.",
        "terminated_sessions": terminated,
    }
