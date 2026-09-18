"""
Module 9 -- Attack Simulation.

    GET  /simulate/scenarios      admin: the live scenario -> label catalogue
                                   (mirrors /security/config, /mfa/config,
                                   /trust-score/config's "live reference"
                                   shape) -- the frontend renders its eight
                                   buttons from this instead of a hardcoded
                                   list.
    POST /simulate/{scenario}     admin: run one Section-5 "Simulate ..."
                                   scenario against a specific, ACTIVE
                                   session. Real backend logic every time --
                                   see app.services.simulation's own
                                   docstring for exactly which existing
                                   Module 3/5/7 function each scenario calls
                                   and why; nothing here is UI-only.

Every scenario except `session_termination` produces a ContinuousEvalResult
(app.services.trust_score.continuous) exactly like the manual admin Trigger
(POST /security/events, Module 7) or the automatic detectors (Section 18,
Section 27) do -- so this endpoint's own extra job, same as security.py's,
is the async WebSocket push that result calls for, via the identical
`push_continuous_result` helper.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session as DbSession

from app.api.deps import CurrentAdmin, get_db
from app.api.v1.endpoints.security import push_continuous_result
from app.schemas.simulation import (
    SimulationRequest,
    SimulationResultOut,
    SimulationScenariosResponse,
)
from app.services import simulation as simulation_service

router = APIRouter()


@router.get(
    "/simulate/scenarios",
    tags=["simulation"],
    response_model=SimulationScenariosResponse,
    summary="The live Attack Simulation scenario catalogue (admin)",
)
def list_scenarios(_admin: CurrentAdmin) -> SimulationScenariosResponse:
    return SimulationScenariosResponse(scenarios=simulation_service.scenario_catalogue())


@router.post(
    "/simulate/{scenario}",
    tags=["simulation"],
    response_model=SimulationResultOut,
    summary="Run one Attack Simulation scenario against an active session (admin)",
)
async def simulate(
    scenario: str,
    payload: SimulationRequest,
    _admin: CurrentAdmin,
    db: DbSession = Depends(get_db),
) -> SimulationResultOut:
    try:
        outcome = simulation_service.run_scenario(
            db, scenario=scenario, session_id=payload.session_id
        )
    except simulation_service.UnknownScenario:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Unknown simulation scenario. Expected one of: "
                + ", ".join(simulation_service.SimulationScenario.ALL)
            ),
        )
    except simulation_service.SessionNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    except simulation_service.SessionNotActive:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Session is not active")

    if outcome.terminated_session is not None:
        session = outcome.terminated_session
        # session_termination isn't a continuous-evaluation event -- it's the
        # exact same call DELETE /sessions/{id} already makes, so it gets the
        # exact same WebSocket push that endpoint already sends (the
        # session.terminated message MUST go out before the close frame --
        # see ConnectionManager.close's own docstring).
        from app.ws.connection_manager import manager  # local: avoid a module-level cycle

        await manager.close(
            session.id,
            code=status.WS_1000_NORMAL_CLOSURE,
            reason="admin_terminated",
            message={"type": "session.terminated", "reason": "admin_terminated"},
        )
        return SimulationResultOut(
            scenario=scenario,
            session_id=session.id,
            state=session.state,
            termination_reason=session.termination_reason,
        )

    # `failed_login` (Section 27's real detector) can affect OTHER active
    # sessions on the same account besides the one the admin selected here
    # -- push those over their own live sockets too, exactly as a genuine
    # password-guessing burst would reach every one of that user's open tabs.
    for other in outcome.other_results:
        await push_continuous_result(other)

    result = outcome.continuous_result
    if result is None:
        # Only reachable for `failed_login` against a session whose account
        # somehow has no resolvable username -- a defensive fallback, not an
        # expected runtime path (every session has a real owning user).
        return SimulationResultOut(scenario=scenario, session_id=payload.session_id)

    await push_continuous_result(result)

    return SimulationResultOut(
        scenario=scenario,
        session_id=result.session_id,
        security_event_id=result.security_event_id,
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
