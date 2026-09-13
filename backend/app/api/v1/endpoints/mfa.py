"""
Module 6 -- Adaptive MFA.

    POST /mfa/verify              exchange an mfa_pending token + emailed code
                                  for a real access token (login MFA step)
    POST /mfa/challenge           step-up: an authenticated user asks for a
                                  fresh challenge (also what Module 7 will call)
    GET  /mfa/challenge/{id}      poll one challenge's status (owner or admin)
    GET  /mfa/challenges          recent challenges feed (admin) -- dashboard
    GET  /mfa/config             the decision policy + email/OTP params (admin)

The login-time decision (allow / MFA / block) lives in /auth/login; this
module owns challenge generation, verification, expiry and retry handling.
Method is always email (TOTP was removed 2026-09-10 -- see
docs/architecture.md and Project status.md section 11).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session as DbSession

from app.api.deps import CurrentAdmin, CurrentUser, get_db
from app.core.config import get_settings
from app.core.security import TokenError, create_access_token, create_mfa_token, decode_mfa_token
from app.models.mfa import MFAChallengeReason
from app.models.session import TerminationReason
from app.schemas.auth import Token, UserRead
from app.schemas.mfa import (
    MFAChallengeListResponse,
    MFAChallengeOut,
    MFAChallengeStatusOut,
    MFAVerifyRequest,
)
from app.services import mfa as mfa_service
from app.services import session as session_service
from app.services import trust_score as trust_score_service
from app.services.auth import get_user_by_id
from app.ws.connection_manager import manager

router = APIRouter()
settings = get_settings()


async def _revoke_retrigger_session(db: DbSession, session_id: str) -> None:
    """A Module 7 risk_retrigger challenge that failed, was exhausted, or
    expired means the user could not re-prove their identity for a session
    that had already dropped to MEDIUM risk -- zero trust says revoke, not
    leave it running. Idempotent: terminate_session() is a no-op if the
    session already ended for some other reason first."""
    updated = session_service.terminate_session(
        db, session_id, reason=TerminationReason.RISK_REVOKED
    )
    if updated is not None:
        await manager.close(
            session_id,
            code=status.WS_1000_NORMAL_CLOSURE,
            reason="risk_revoked",
            message={"type": "session.terminated", "reason": TerminationReason.RISK_REVOKED},
        )


def _issue_access_token(user) -> Token:
    return Token(
        access_token=create_access_token(user.id),
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserRead.model_validate(user),
    )


@router.post(
    "/mfa/verify",
    tags=["mfa"],
    response_model=Token,
    summary="Verify the emailed code and exchange the mfa_pending token for access",
)
async def verify_mfa(payload: MFAVerifyRequest, db: DbSession = Depends(get_db)) -> Token:
    try:
        claims = decode_mfa_token(payload.mfa_token)
    except TokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA token"
        )

    user_id = int(claims["sub"])
    challenge = mfa_service.get_challenge(db, claims["cid"])
    if challenge is None or challenge.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Challenge not found")

    # Module 7: a risk_retrigger challenge is scoped to the session that
    # triggered it. On failure/expiry that session gets revoked, not just the
    # challenge (see _revoke_retrigger_session above).
    is_retrigger = challenge.reason == MFAChallengeReason.RISK_RETRIGGER
    retrigger_session_id = challenge.session_id if is_retrigger else None

    try:
        mfa_service.verify_challenge(db, challenge=challenge, code=payload.code)
    except mfa_service.ChallengeExpired:
        if retrigger_session_id:
            await _revoke_retrigger_session(db, retrigger_session_id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"message": "MFA challenge expired", "code": "expired"},
        )
    except mfa_service.ChallengeExhausted:
        if retrigger_session_id:
            await _revoke_retrigger_session(db, retrigger_session_id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"message": "Too many attempts -- restart login", "code": "exhausted"},
        )
    except mfa_service.ChallengeNotPending:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"message": "Challenge is no longer open", "code": "closed"},
        )
    except mfa_service.InvalidCode as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Invalid code",
                "code": "invalid",
                "attempts_remaining": exc.attempts_remaining,
            },
        )

    if retrigger_session_id:
        # Passing re-verification proves identity again -- it does not
        # restore the trust score the triggering event already knocked down
        # (the underlying signal, e.g. still being on an unknown VPN, is
        # still true). It clears the "reverify_required" banner client-side.
        await manager.send(
            retrigger_session_id,
            {"type": "trust.reverified", "session_id": retrigger_session_id},
        )

    user = get_user_by_id(db, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User unavailable")
    return _issue_access_token(user)


@router.post(
    "/mfa/challenge",
    tags=["mfa"],
    response_model=MFAChallengeOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a fresh MFA challenge for the current user (step-up)",
)
def create_step_up_challenge(
    current_user: CurrentUser, db: DbSession = Depends(get_db)
) -> MFAChallengeOut:
    # snapshot the caller's current trust context on the challenge, for the feed
    try:
        evaluation = trust_score_service.evaluate_login(
            db, user_id=current_user.id, ip_address=None, user_agent=None
        )
        score, risk = evaluation.score, evaluation.risk_level
    except Exception:  # noqa: BLE001 - the challenge must still be creatable
        score, risk = None, None

    try:
        challenge = mfa_service.create_challenge(
            db, user=current_user, reason=MFAChallengeReason.STEP_UP,
            trust_score=score, risk_level=risk,
        )
    except mfa_service.DeliveryFailed:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not send the verification email. Try again shortly.",
        )
    mfa_token = create_mfa_token(
        current_user.id, challenge.id, expires_minutes=settings.mfa_challenge_ttl_minutes
    )
    return mfa_service.build_challenge_out(challenge, mfa_token=mfa_token)


@router.get(
    "/mfa/challenge/{challenge_id}",
    tags=["mfa"],
    response_model=MFAChallengeStatusOut,
    summary="Poll one challenge's status (owner or admin)",
)
def get_challenge_status(
    challenge_id: str, current_user: CurrentUser, db: DbSession = Depends(get_db)
) -> MFAChallengeStatusOut:
    challenge = mfa_service.get_challenge(db, challenge_id)
    if challenge is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Challenge not found")
    if not current_user.is_admin and challenge.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not your challenge")
    return MFAChallengeStatusOut.model_validate(challenge)


@router.get(
    "/mfa/challenges",
    tags=["mfa"],
    response_model=MFAChallengeListResponse,
    summary="Recent MFA challenges (admin) -- dashboard MFA events feed",
)
def list_challenges(
    _admin: CurrentAdmin,
    db: DbSession = Depends(get_db),
    status_filter: str | None = Query(default=None, alias="status"),
) -> MFAChallengeListResponse:
    rows = mfa_service.list_recent_challenges(db, status=status_filter)
    return MFAChallengeListResponse(
        challenges=[MFAChallengeStatusOut.model_validate(r) for r in rows],
        counts=mfa_service.count_by_status(db),
    )


@router.get(
    "/mfa/config",
    tags=["mfa"],
    summary="The MFA decision policy + email/OTP parameters (admin)",
)
def mfa_config(_admin: CurrentAdmin) -> dict:
    return {
        "mfa_enabled": settings.mfa_enabled,
        "decision": {
            "allow": f"risk LOW (score >= {settings.trust_risk_low_min})",
            "mfa": f"risk MEDIUM (score {settings.trust_risk_medium_min}-{settings.trust_risk_low_min - 1})",
            "block": f"risk HIGH (score < {settings.trust_risk_medium_min})",
        },
        "challenge_ttl_minutes": settings.mfa_challenge_ttl_minutes,
        "max_attempts": settings.mfa_max_attempts,
        "email": {
            "method": "email",
            "otp_length": settings.mfa_otp_length,
            "smtp_configured": bool(settings.smtp_username and settings.smtp_password),
        },
    }
