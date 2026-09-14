"""
Module 7 -- Continuous Trust Evaluation.

    POST /security/events    ingest one security-relevant event for an
                              ACTIVE session (admin today; also the entry
                              point Module 9's future simulation buttons will
                              call) -- recomputes the session's trust score
                              against its CURRENT value and carries out the
                              resulting risk-based action (none / reverify /
                              revoke). The session's own live WebSocket
                              always gets a push either way: `trust.updated`
                              for `none` (2026-09-14), `trust.reverify_required`
                              for `reverify`, `session.terminated` for `revoke`.
    GET  /security/events    recent continuous-evaluation events (admin) --
                              dashboard feed, optionally filtered to one
                              session.
    GET  /security/config    the live event-type -> weight/action table
                              (admin) -- reference view, mirrors
                              /trust-score/config and /mfa/config.

The scoring/action logic lives in app.services.trust_score.continuous (a
composition of the existing trust_score + mfa + session services -- no new
service package, per docs/architecture.md). That module is sync, like every
other service in this codebase; this endpoint's only extra job is the async
WebSocket push/close its result says to perform.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session as DbSession

from app.api.deps import CurrentAdmin, get_db
from app.core.config import get_settings
from app.core.security import create_mfa_token
from app.models.security_event import SecurityEventType
from app.schemas.security import (
    SecurityEventListResponse,
    SecurityEventReadOut,
    SecurityEventRequest,
    SecurityEventResultOut,
)
from app.services import mfa as mfa_service
from app.services.trust_score import continuous as continuous_service
from app.ws.connection_manager import manager

router = APIRouter()
settings = get_settings()


@router.post(
    "/security/events",
    tags=["security"],
    response_model=SecurityEventResultOut,
    summary="Ingest a security-relevant event for an active session (admin) -- Module 7",
)
async def ingest_security_event(
    payload: SecurityEventRequest, _admin: CurrentAdmin, db: DbSession = Depends(get_db)
) -> SecurityEventResultOut:
    if payload.event_type not in SecurityEventType.ALL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown event_type. Expected one of: {', '.join(SecurityEventType.ALL)}",
        )

    try:
        result = continuous_service.record_event(
            db,
            session_id=payload.session_id,
            event_type=payload.event_type,
            ip_address=payload.ip_address,
        )
    except continuous_service.SessionNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    except continuous_service.SessionNotActive:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Session is not active"
        )

    # The service layer stays sync (see continuous.py's docstring); the
    # WebSocket push/close its result calls for happens here. The pushed
    # `challenge` is a full MFAChallengeOut (mfa_token included) -- exactly
    # what the client needs to complete re-verification at POST /mfa/verify,
    # the same shape /auth/login already hands back for the login-time MFA
    # step (see app/services/mfa/service.build_challenge_out).
    if result.should_push_reverify and result.mfa_challenge is not None:
        mfa_token = create_mfa_token(
            result.user_id, result.mfa_challenge.id,
            expires_minutes=settings.mfa_challenge_ttl_minutes,
        )
        challenge_out = mfa_service.build_challenge_out(result.mfa_challenge, mfa_token=mfa_token)
        await manager.send(
            result.session_id,
            {
                "type": "trust.reverify_required",
                "session_id": result.session_id,
                "risk_level": result.new_risk,
                "trust_score": result.new_score,
                "challenge": challenge_out.model_dump(mode="json"),
            },
        )
    elif result.should_close_session:
        await manager.close(
            result.session_id,
            code=status.WS_1000_NORMAL_CLOSURE,
            reason="risk_revoked",
            message={"type": "session.terminated", "reason": "risk_revoked"},
        )
    else:
        # action == NONE -- the event was recorded and the session's score
        # WAS updated in the DB (continuous_service.record_event always
        # persists it), it just didn't cross a risk-band boundary that
        # warrants a challenge or a revoke. Still push it (2026-09-14 fix):
        # without this, a session's own tab (User Portal) only ever learns
        # its score changed on the event that finally crosses into MEDIUM/
        # HIGH, so several quiet in-band drops (e.g. 100 -> 90 -> 80, still
        # LOW) would be invisible there even though the admin's Live
        # Sessions table -- which polls the DB directly -- shows every one
        # of them immediately. This message never ends the session and
        # never opens the reverify modal; it only keeps a live numeric
        # display in sync.
        await manager.send(
            result.session_id,
            {
                "type": "trust.updated",
                "session_id": result.session_id,
                "risk_level": result.new_risk,
                "trust_score": result.new_score,
            },
        )

    return SecurityEventResultOut(
        security_event_id=result.security_event_id,
        session_id=result.session_id,
        event_type=result.event_type,
        weight_applied=result.weight_applied,
        reason=result.reason,
        previous_score=result.previous_score,
        new_score=result.new_score,
        previous_risk=result.previous_risk,
        new_risk=result.new_risk,
        action=result.action,
        mfa_challenge_id=result.mfa_challenge.id if result.mfa_challenge else None,
    )


@router.get(
    "/security/events",
    tags=["security"],
    response_model=SecurityEventListResponse,
    summary="Recent continuous-evaluation events (admin) -- dashboard feed",
)
def list_security_events(
    _admin: CurrentAdmin,
    db: DbSession = Depends(get_db),
    session_id: str | None = Query(default=None, description="Filter to one session"),
    limit: int = Query(default=100, ge=1, le=500),
) -> SecurityEventListResponse:
    rows = continuous_service.list_recent_events(db, session_id=session_id, limit=limit)
    return SecurityEventListResponse(
        events=[SecurityEventReadOut.model_validate(r) for r in rows]
    )


@router.get(
    "/security/config",
    tags=["security"],
    summary="The continuous-evaluation event catalogue + weights/actions (admin)",
)
def security_config(_admin: CurrentAdmin) -> dict:
    return continuous_service.event_catalogue()
