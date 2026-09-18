"""
services/simulation/ -> Module 9: Attack Simulation.

  service.py   thin, admin-only dispatch layer over the REAL backend
               mechanisms Modules 3/5/7 already built (continuous.record_event,
               trust_score_service.record_failed_login_attempt,
               session_service.terminate_session) -- one function per
               Section 5 "Simulate ..." button. No scoring/revocation logic
               of its own; see service.py's own docstring for exactly which
               existing function each of the eight scenarios calls.

Kept as its own package (this directory has existed as an empty scaffold
since Module 1's initial project layout) to match this project's
one-sub-package-per-module convention, alongside auth/ session/ acl/
trust_score/ mfa/ dashboard/.
"""
from app.services.simulation.service import (
    SessionNotActive,
    SessionNotFound,
    SimulationError,
    SimulationOutcome,
    SimulationScenario,
    UnknownScenario,
    pick_sample_ip,
    run_scenario,
    scenario_catalogue,
)

__all__ = [
    "SessionNotActive",
    "SessionNotFound",
    "SimulationError",
    "SimulationOutcome",
    "SimulationScenario",
    "UnknownScenario",
    "pick_sample_ip",
    "run_scenario",
    "scenario_catalogue",
]
