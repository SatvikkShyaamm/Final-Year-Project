"""
Module 7 -- Continuous Trust Evaluation.

    POST /security/events     ingest one security-relevant event for an
                               ACTIVE session (admin today; also the entry
                               point Module 9's future simulation buttons will
                               call) -- recomputes the session's trust score
                               against its CURRENT value and carries out the
                               resulting risk-based action (none / reverify /
                               revoke). The session's own live WebSocket
                               always gets a push either way: `trust.updated`
                               for `none` (2026-09-14), `trust.reverify_required`
                               for `reverify`, `session.terminated` for `revoke`.
    POST /security/heartbeat  Section 18 (2026-09-15, "Real Passive Network
                               Detection") -- any authenticated user's own
                               periodic, automatic counterpart to the manual
                               Trigger above. No body: the caller's own
                               current ACTIVE session is resolved server-side
                               and this request's own real IP/User-Agent are
                               compared against that session's last-observed
                               values, firing the identical
                               continuous.record_event pipeline (source=auto)
                               on a genuine change. See
                               app.services.trust_score.heartbeat for the
                               detection mechanism itself.
    GET  /security/events     recent continuous-evaluation events (admin) --
                               dashboard feed, optionally filtered to one
                               session and/or one source (auto | admin).
    GET  /security/config     the live event-type -> weight/action table
                               (admin) -- reference view, mirrors
                               /trust-score/config and /mfa/config.

The scoring/action logic lives in app.services.trust_score.continuous (a
composition of the existing trust_score + mfa + session services -- no new
service package, per docs/architecture.md). That module is sync, like every
other service in this codebase; this endpoint's only extra job is the async
WebSocket push/close its result says to perform -- shared by every path that
can produce a ContinuousEvalResult via `push_continuous_result` below, so a
real detection looks, live, identical to a manual admin Trigger from the
session's own tab's point of view (Section 18's own requirement: "no admin
Trigger click involved anywhere in the path"). Besides this endpoint's own
two POST handlers, `push_continuous_result` is also imported directly by
`POST /auth/login` (2026-09-17 hardening) to push the results of an
automatically-detected `multiple_failed_logins` burst against any of the
account's other active sessions -- see
app.services.trust_score.service.record_failed_login_attempt.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session as DbSession

from app.api.deps import CurrentAdmin, CurrentUser, get_db
from app.core.config import get_settings
from app.core.security import create_mfa_token
from app.models.security_event import SecurityEventSource, SecurityEventType
from app.models.session import SessionState
from app.schemas.security import (
    HeartbeatResultOut,
    SecurityEventListResponse,
    SecurityEventReadOut,
    SecurityEventRequest,
    SecurityEventResultOut,
)
from app.services import mfa as mfa_service
from app.services import session as session_service
from app.services.trust_score import continuous as continuous_service
from app.services.trust_score import heartbeat as heartbeat_service
from app.ws.connection_manager import manager

router = APIRouter()
settings = get_settings()


def _client_ip(request: Request) -> str | None:
    """Real client IP for a plain HTTP request -- mirrors sessions.py's own
    `_client_ip` (WebSocket-specific there, since it reads `websocket.
    headers`/`websocket.client` instead of `request.headers`/`request.
    client`), so the deployment requirement documented there (a trusted
    reverse proxy setting X-Forwarded-For) covers this endpoint too."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


async def push_continuous_result(result: continuous_service.ContinuousEvalResult) -> None:
    """The WebSocket push/close one continuous-evaluation result calls for --
    identical regardless of whether `result` came from a manual admin
    Trigger, the automatic heartbeat detector (Section 18), or the
    automatic multiple-failed-logins detector (2026-09-17, called directly
    from POST /auth/login). Not prefixed with an underscore: it is
    deliberately importable from outside this module for exactly that last
    case -- see the module docstring."""
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
        # action == NONE -- still push it (2026-09-14 fix, see the module
        # docstring above): a client tracking the live score must see every
        # step, not just the one that eventually crosses a risk-band boundary.
        await manager.send(
            result.session_id,
            {
                "type": "trust.updated",
                "session_id": result.session_id,
                "risk_level": result.new_risk,
                "trust_score": result.new_score,
            },
        )


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
            source=SecurityEventSource.ADMIN,
        )
    except continuous_service.SessionNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    except continuous_service.SessionNotActive:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Session is not active"
        )

    # The service layer stays sync (see continuous.py's docstring); the
    # WebSocket push/close its result calls for happens here, via the same
    # `push_continuous_result` helper the automatic heartbeat path (below)
    # and POST /auth/login's automatic multiple-failed-logins path also use.
    await push_continuous_result(result)

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
        source=result.source,
        mfa_challenge_id=result.mfa_challenge.id if result.mfa_challenge else None,
    )


@router.post(
    "/security/heartbeat",
    tags=["security"],
    response_model=HeartbeatResultOut,
    summary="Passive network heartbeat for the caller's own active session -- Module 7 Section 18",
)
async def security_heartbeat(
    request: Request, current_user: CurrentUser, db: DbSession = Depends(get_db)
) -> HeartbeatResultOut:
    row = session_service.get_current_session_for_user(db, current_user.id)
    if row is None or row.state != SessionState.ACTIVE:
        # Best-effort telemetry, not a user-facing action -- a heartbeat that
        # lands with no active session (a brief race around login/logout, a
        # stale tab) is simply a no-op, never an error the frontend has to
        # handle specially.
        return HeartbeatResultOut(session_id=None, seeded=False, events=[])

    try:
        result = heartbeat_service.record_heartbeat(
            db,
            session_id=row.id,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except continuous_service.SessionNotActive:
        return HeartbeatResultOut(session_id=row.id, seeded=False, events=[])

    for eval_result in result.events:
        await push_continuous_result(eval_result)

    return HeartbeatResultOut(
        session_id=result.session_id,
        seeded=result.seeded,
        events=[e.event_type for e in result.events],
        session_terminated=result.session_terminated,
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
    source: str | None = Query(
        default=None, description="Filter to one source: auto | admin (Section 18)"
    ),
    limit: int = Query(default=100, ge=1, le=500),
) -> SecurityEventListResponse:
    if source is not None and source not in SecurityEventSource.ALL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown source. Expected one of: {', '.join(SecurityEventSource.ALL)}",
        )
    rows = continuous_service.list_recent_events(
        db, session_id=session_id, source=source, limit=limit
    )
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
