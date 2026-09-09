"""
Module 5 — Trust Score Engine (read surface).

    GET /trust-score/config                    admin: the live weight table + bands
    GET /trust-score/user/{user_id}/history    admin or self: past session scores
    GET /trust-score/{session_id}              admin or owner: score + factor breakdown

The score itself is computed and stored by the session_opened hook
(app/services/trust_score) — there is nothing to POST here. Module 5 only
*reports* the score; turning it into an allow / MFA / block decision is
Module 6.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session as DbSession

from app.api.deps import CurrentAdmin, CurrentUser, get_db
from app.core.config import get_settings
from app.schemas.trust_score import (
    SessionTrustScoreRead,
    TrustFactorCatalogEntry,
    TrustFactorRead,
    TrustScoreConfigResponse,
    TrustScoreHistoryEntry,
    TrustScoreHistoryResponse,
)
from app.services import session as session_service
from app.services import trust_score as trust_service
from app.services.auth import get_user_by_id

router = APIRouter()
settings = get_settings()


@router.get(
    "/trust-score/config",
    tags=["trust-score"],
    response_model=TrustScoreConfigResponse,
    summary="The live trust-score weight table + risk bands (admin)",
)
def get_trust_config(_admin: CurrentAdmin) -> TrustScoreConfigResponse:
    return TrustScoreConfigResponse(
        baseline=settings.trust_score_baseline,
        risk_bands=trust_service.risk_bands(),
        factors=[TrustFactorCatalogEntry(**f) for f in trust_service.factor_catalogue()],
        failed_login_threshold=settings.trust_failed_login_threshold,
        failed_login_window_minutes=settings.trust_failed_login_window_minutes,
        approved_vpn_cidrs=settings.trust_approved_vpn_cidrs,
        known_vpn_cidrs=settings.trust_known_vpn_cidrs,
    )


@router.get(
    "/trust-score/user/{user_id}/history",
    tags=["trust-score"],
    response_model=TrustScoreHistoryResponse,
    summary="A user's past session trust scores (admin, or the user themselves)",
)
def get_user_trust_history(
    user_id: int, current_user: CurrentUser, db: DbSession = Depends(get_db)
) -> TrustScoreHistoryResponse:
    if not current_user.is_admin and current_user.id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not your history")
    user = get_user_by_id(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    rows = trust_service.get_user_score_history(db, user_id)
    scored = [r.trust_score for r in rows if r.trust_score is not None]
    return TrustScoreHistoryResponse(
        user_id=user_id,
        username=user.username,
        entries=[
            TrustScoreHistoryEntry(
                session_id=r.id,
                trust_score=r.trust_score,
                risk_level=r.risk_level,
                created_at=r.created_at,
                ip_address=r.ip_address,
                state=r.state,
            )
            for r in rows
        ],
        average_trust_score=round(sum(scored) / len(scored), 2) if scored else None,
    )


@router.get(
    "/trust-score/{session_id}",
    tags=["trust-score"],
    response_model=SessionTrustScoreRead,
    summary="One session's trust score + per-factor breakdown (admin or owner)",
)
def get_session_trust_score(
    session_id: str, current_user: CurrentUser, db: DbSession = Depends(get_db)
) -> SessionTrustScoreRead:
    session = session_service.get_session(db, session_id)
    if session is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    if not current_user.is_admin and session.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not your session")

    factors = trust_service.get_factors_for_session(db, session_id)
    return SessionTrustScoreRead(
        session_id=session.id,
        user_id=session.user_id,
        username=session.username,
        trust_score=session.trust_score,
        risk_level=session.risk_level,
        evaluated_at=factors[0].created_at if factors else session.created_at,
        factors=[TrustFactorRead.model_validate(f) for f in factors],
    )
