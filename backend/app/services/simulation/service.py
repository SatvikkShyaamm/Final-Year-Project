"""
Attack Simulation -- Module 9.

Thin, admin-only dispatch layer over the REAL backend mechanisms Modules
3/5/7 already built. Per Section 15 of MASTER_PROJECT_CONTEXT.docx ("these
should trigger the actual backend logic rather than simply changing text on
the UI"), this module invents no scoring/revocation logic of its own -- it
only decides, for each of Section 5's eight named "Simulate ..." buttons,
which already-real function to call and with what input:

    Simulate IP Change          -> continuous.record_event(ip_change)
    Simulate Approved VPN       -> continuous.record_event(vpn_detected),
                                    fed a real IP drawn from
                                    trust_approved_vpn_cidrs (Section 6's
                                    "Attack Simulation -- VPN buttons" note:
                                    two independent, self-contained buttons,
                                    not a generic VPN toggle)
    Simulate Unknown VPN        -> the same, fed an IP from
                                    trust_known_vpn_cidrs instead
    Simulate Unknown Device     -> continuous.record_event(unknown_device)
    Simulate Large Download     -> continuous.record_event(large_download)
                                    (deliberately simulate-only -- Section 18
                                    itself keeps this out of scope for real
                                    passive detection: there is no real
                                    protected-resource download endpoint to
                                    measure a genuine transfer against)
    Simulate Abnormal Requests  -> continuous.record_event(abnormal_request_rate)
    Simulate Multiple Failed
      Login                     -> the REAL detector (Section 27):
                                    trust_score_service.
                                    record_failed_login_attempt(), called
                                    trust_failed_login_threshold times in a
                                    row against the target session's own
                                    username -- exercising the identical
                                    Redis burst counter and fire-once guard
                                    a genuine password-guessing attacker
                                    would trip, hitting every one of that
                                    account's active sessions (not only the
                                    one chosen here), matching the real
                                    mechanism exactly.
    Simulate Session Termination -> session_service.terminate_session(
                                    reason=ADMIN_TERMINATED) -- the
                                    identical call DELETE /sessions/{id}
                                    already makes.

Why the first five call continuous.record_event() directly rather than
routing through the Section 18 heartbeat/request-rate detectors, even
though those are now real for ip_change/vpn_detected/unknown_device/
abnormal_request_rate: those detectors compare against Redis-held "last
observed" state that depends on whether/when a real heartbeat already ran
for that session -- a polished, always-reliable demo control cannot assume
that. Calling continuous.record_event() directly is the exact same call the
admin Trigger control (POST /security/events, Module 7) already makes, so
these five scenarios are precisely equivalent to that pre-existing path
with a friendlier name and (for the two VPN buttons) an automatically
chosen IP instead of a manually typed one. `failed_login`, by contrast, is
Redis-counter-only with no unpredictable comparison state, so it safely
reuses the real detector end to end for a strictly more faithful
simulation -- and `session_termination` isn't a continuous-evaluation event
at all, so it calls the session layer directly.

No FastAPI imports; the endpoint (app/api/v1/endpoints/simulation.py) is
the only caller, and owns the async WebSocket push its result calls for
(the ContinuousEvalResult path reuses security.py's existing
push_continuous_result helper unchanged).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from sqlalchemy.orm import Session as DbSession

from app.core.config import get_settings
from app.models.security_event import SecurityEventSource, SecurityEventType
from app.models.session import Session as SessionModel
from app.models.session import SessionState, TerminationReason
from app.services import session as session_service
from app.services import trust_score as trust_score_service
from app.services.trust_score import continuous as continuous_service

settings = get_settings()

# RFC 5737 TEST-NET-3 -- a documentation-reserved range, deliberately outside
# both configured VPN CIDR lists, so "Simulate IP Change" always classifies
# as a plain ip_change (never accidentally landing in trust_approved_vpn_cidrs
# / trust_known_vpn_cidrs and getting reclassified as vpn_detected).
SIMULATED_NEW_IP = "203.0.113.10"


class SimulationScenario:
    IP_CHANGE = "ip_change"
    APPROVED_VPN = "approved_vpn"
    UNKNOWN_VPN = "unknown_vpn"
    UNKNOWN_DEVICE = "unknown_device"
    LARGE_DOWNLOAD = "large_download"
    ABNORMAL_REQUESTS = "abnormal_requests"
    FAILED_LOGIN = "failed_login"
    SESSION_TERMINATION = "session_termination"

    ALL = (
        IP_CHANGE,
        APPROVED_VPN,
        UNKNOWN_VPN,
        UNKNOWN_DEVICE,
        LARGE_DOWNLOAD,
        ABNORMAL_REQUESTS,
        FAILED_LOGIN,
        SESSION_TERMINATION,
    )

    LABELS = {
        IP_CHANGE: "Simulate IP Change",
        APPROVED_VPN: "Simulate Approved VPN",
        UNKNOWN_VPN: "Simulate Unknown VPN",
        UNKNOWN_DEVICE: "Simulate Unknown Device",
        LARGE_DOWNLOAD: "Simulate Large Download",
        ABNORMAL_REQUESTS: "Simulate Abnormal Requests",
        FAILED_LOGIN: "Simulate Multiple Failed Login",
        SESSION_TERMINATION: "Simulate Session Termination",
    }

# Every scenario except FAILED_LOGIN and SESSION_TERMINATION maps 1:1 onto an
# existing SecurityEventType and is fired via continuous.record_event().
_EVENT_TYPE_FOR_SCENARIO = {
    SimulationScenario.IP_CHANGE: SecurityEventType.IP_CHANGE,
    SimulationScenario.APPROVED_VPN: SecurityEventType.VPN_DETECTED,
    SimulationScenario.UNKNOWN_VPN: SecurityEventType.VPN_DETECTED,
    SimulationScenario.UNKNOWN_DEVICE: SecurityEventType.UNKNOWN_DEVICE,
    SimulationScenario.LARGE_DOWNLOAD: SecurityEventType.LARGE_DOWNLOAD,
    SimulationScenario.ABNORMAL_REQUESTS: SecurityEventType.ABNORMAL_REQUEST_RATE,
}


class SimulationError(Exception):
    pass


class SessionNotFound(SimulationError):
    pass


class SessionNotActive(SimulationError):
    pass


class UnknownScenario(SimulationError):
    def __init__(self, scenario: str) -> None:
        super().__init__(f"unknown simulation scenario: {scenario!r}")
        self.scenario = scenario


@dataclass
class SimulationOutcome:
    scenario: str
    session_id: str
    continuous_result: continuous_service.ContinuousEvalResult | None = None
    # Set only for `failed_login`: the REAL detector hits every active
    # session on the account, not just the one the admin selected -- these
    # are the OTHER sessions' own results, which the caller must ALSO push
    # over their own live sockets (the same way a genuine password-guessing
    # burst would reach every one of that user's open tabs).
    other_results: list[continuous_service.ContinuousEvalResult] = field(default_factory=list)
    terminated_session: SessionModel | None = None


def pick_sample_ip(cidrs: list[str]) -> str | None:
    """The first usable host address in the first parseable CIDR block --
    used to give "Simulate Approved VPN" / "Simulate Unknown VPN" a real,
    classifiable source IP automatically, per Section 6's "Attack
    Simulation -- VPN buttons" note (the admin picks a scenario, not an IP).
    None if the configured list is empty or entirely unparseable (the
    resulting event would then fall back to the generic "not in either
    list" classification -- see continuous.classify_event)."""
    for raw in cidrs:
        try:
            network = ipaddress.ip_network(raw.strip(), strict=False)
        except ValueError:
            continue
        for host in network.hosts():
            return str(host)
        return str(network.network_address)  # e.g. a /31 or /32 with no hosts() members
    return None


def run_scenario(db: DbSession, *, scenario: str, session_id: str) -> SimulationOutcome:
    """Run one Section-5 "Simulate ..." scenario against a specific, ACTIVE
    session. Raises SessionNotFound / SessionNotActive / UnknownScenario;
    the caller maps these to HTTP."""
    if scenario not in SimulationScenario.ALL:
        raise UnknownScenario(scenario)

    session = session_service.get_session(db, session_id)
    if session is None:
        raise SessionNotFound(session_id)
    if session.state != SessionState.ACTIVE:
        raise SessionNotActive(session_id)

    if scenario == SimulationScenario.SESSION_TERMINATION:
        terminated = session_service.terminate_session(
            db, session_id, reason=TerminationReason.ADMIN_TERMINATED
        )
        return SimulationOutcome(
            scenario=scenario, session_id=session_id, terminated_session=terminated
        )

    if scenario == SimulationScenario.FAILED_LOGIN:
        username = session.username
        results: list[continuous_service.ContinuousEvalResult] = []
        if username is not None:
            for _ in range(max(1, settings.trust_failed_login_threshold)):
                results.extend(
                    trust_score_service.record_failed_login_attempt(db, username=username)
                )
        # The real detector hits every active session on the account; report
        # back specifically the outcome for the session the admin selected
        # (falling back to any result at all if that one somehow isn't in
        # the list -- it always will be, since it was just confirmed ACTIVE
        # above and record_failed_login_attempt targets every active session
        # on the account, this one included) -- and hand back every OTHER
        # session's own result too, so the caller can push those over their
        # own live sockets as well (see other_results' docstring above).
        primary = next(
            (r for r in results if r.session_id == session_id), results[0] if results else None
        )
        others = [r for r in results if r is not primary]
        return SimulationOutcome(
            scenario=scenario, session_id=session_id,
            continuous_result=primary, other_results=others,
        )

    event_type = _EVENT_TYPE_FOR_SCENARIO[scenario]
    ip_address: str | None = None
    if scenario == SimulationScenario.IP_CHANGE:
        ip_address = SIMULATED_NEW_IP
    elif scenario == SimulationScenario.APPROVED_VPN:
        ip_address = pick_sample_ip(settings.trust_approved_vpn_cidrs)
    elif scenario == SimulationScenario.UNKNOWN_VPN:
        ip_address = pick_sample_ip(settings.trust_known_vpn_cidrs)

    result = continuous_service.record_event(
        db,
        session_id=session_id,
        event_type=event_type,
        ip_address=ip_address,
        source=SecurityEventSource.ADMIN,
    )
    return SimulationOutcome(scenario=scenario, session_id=session_id, continuous_result=result)


def scenario_catalogue() -> list[dict]:
    """The live scenario -> label table, for the frontend to render its
    buttons from a single source of truth (mirrors trust_score.
    factor_catalogue / mfa.mfa_config / continuous.event_catalogue)."""
    return [
        {"scenario": scenario, "label": SimulationScenario.LABELS[scenario]}
        for scenario in SimulationScenario.ALL
    ]
