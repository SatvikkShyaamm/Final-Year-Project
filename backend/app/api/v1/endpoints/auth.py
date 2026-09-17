"""
Authentication endpoints — Module 2, with the Module 6 risk gate on /auth/login.

    POST /auth/register  -> create account, return JWT + user (no MFA gate:
                            you just created + proved these credentials in this
                            same request; the risk gate is on *returning*)
    POST /auth/login     -> verify credentials, then (2026-09-14) an
                            account-level risk-lockout check, then a
                            trust-score decision:
                            LOW   -> access token
                            MEDIUM -> `mfa_required` + an mfa_pending token to
                                      complete at POST /mfa/verify (a code
                                      emailed to the user's registered address)
                            HIGH  -> HTTP 403 (blocked by risk policy)
                            A locked-out account gets HTTP 423 instead, once
                            its password has already been verified -- see
                            app.services.trust_score.risk_lockout.
                            A credential FAILURE (2026-09-17 hardening) also
                            feeds the same burst counter into a mid-session
                            `multiple_failed_logins` Module 7 event against
                            any of this account's OTHER currently active
                            sessions -- see
                            app.services.trust_score.service.
                            record_failed_login_attempt and Project
                            status.md's Module 7 hardening log. `login` is
                            `async` (like `logout` below) purely so it can
                            await the WebSocket push that event calls for;
                            everything else about this endpoint is unchanged.
    GET  /auth/me        -> current user (requires a real Bearer access token)
    POST /auth/logout    -> terminate the user's active session(s)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, get_db
from app.api.v1.endpoints.security import push_continuous_result
from app.core.config import get_settings
from app.core.security import create_access_token, create_mfa_token
from app.models.session import TerminationReason
from app.schemas.auth import LoginRequest, LoginResponse, Token, UserCreate, UserRead
from app.services import mfa as mfa_service
from app.services import session as session_service
from app.services import trust_score as trust_score_service
from app.services.trust_score import risk_lockout
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


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


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
    response_model=LoginResponse,
    summary="Verify credentials, then apply the trust-score risk gate",
)
async def login(
    payload: LoginRequest, request: Request, db: Session = Depends(get_db)
) -> LoginResponse:
    try:
        user = authenticate_user(
            db, username=payload.username, password=payload.password
        )
    except InvalidCredentialsError as exc:
        # Feed Module 5's failed-login burst counter (Redis, 15-min TTL). Only
        # counts against a known username; a no-op otherwise. Since
        # 2026-09-17, this can ALSO return a live continuous-evaluation
        # result per one of this account's OTHER currently active sessions,
        # if this failure is the one that pushed the burst counter at/over
        # its threshold for the first time in the current window -- see
        # record_failed_login_attempt's own docstring. Pushed over each
        # affected session's own WebSocket before this failed attempt's
        # ordinary 401 is returned; the two are unrelated to each other
        # (this request still gets a plain 401 either way).
        affected = trust_score_service.record_failed_login_attempt(
            db, username=payload.username
        )
        for result in affected:
            await push_continuous_result(result)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ---- Account-level RISK lockout (2026-09-14 hardening) ----
    # Checked ONLY here, after the password has already been verified above
    # -- never before it -- so a wrong-password probe against a locked
    # account still gets the ordinary generic 401 above and can't be used to
    # learn that the account exists and is currently locked out
    # (enumeration-safety; same principle the MFA lockout already follows).
    # Account-wide: this blocks the login regardless of which device/
    # User-Agent this particular attempt is coming from.
    retry_after = risk_lockout.lockout_remaining_seconds(user.id)
    if retry_after is not None:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail={
                "message": (
                    "This account was locked after a session was terminated "
                    f"for high security risk -- try again in "
                    f"{retry_after // 3600 + 1} more hour(s)"
                ),
                "code": "risk_locked",
                "retry_after_seconds": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )

    # ---- Module 6: trust-score risk decision (Section 6 bands) ----
    evaluation = trust_score_service.evaluate_login(
        db,
        user_id=user.id,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    decision = mfa_service.decide(evaluation.risk_level)

    if decision == mfa_service.Decision.BLOCK:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Access blocked by risk policy",
                "decision": decision,
                "trust_score": evaluation.score,
                "risk_level": evaluation.risk_level,
            },
        )

    if decision == mfa_service.Decision.ALLOW:
        token = _issue_token(user)
        return LoginResponse(
            mfa_required=False,
            decision=decision,
            trust_score=evaluation.score,
            risk_level=evaluation.risk_level,
            access_token=token.access_token,
            token_type=token.token_type,
            expires_in=token.expires_in,
            user=token.user,
        )

    # decision == MFA
    try:
        challenge = mfa_service.create_challenge(
            db, user=user, trust_score=evaluation.score, risk_level=evaluation.risk_level
        )
    except mfa_service.DeliveryFailed:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not send the verification email. Try again shortly.",
        )
    mfa_token = create_mfa_token(
        user.id, challenge.id, expires_minutes=settings.mfa_challenge_ttl_minutes
    )
    return LoginResponse(
        mfa_required=True,
        decision=decision,
        trust_score=evaluation.score,
        risk_level=evaluation.risk_level,
        mfa=mfa_service.build_challenge_out(challenge, mfa_token=mfa_token),
    )


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
