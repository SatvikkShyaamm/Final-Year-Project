"""
The session finite-state machine — Module 3.

Maps directly onto the base paper's ZTSAACM FSM:

    S0  unauthenticated        -> no Session row (Module 2 territory)
    S1  authenticated          -> user has a JWT but no ACTIVE session
    S2  session active         -> SessionState.ACTIVE
                                  (Module 4 attaches an ACL rule to this state)
    S3  revocation in progress -> collapsed here: termination is synchronous,
                                  so ACTIVE goes straight to TERMINATED. If
                                  Module 4's ACL teardown ever becomes async a
                                  CLOSING state slots in between.

Module 3 owns the S1->S2 open and the S2->S3 close. It does NOT decide whether
an open is *allowed* — that gate is Modules 5 (trust score) and 6 (MFA).
"""
from __future__ import annotations

from app.models.session import SessionState

# current-state -> set of states it may move to. ``None`` = "no session yet".
_ALLOWED: dict[str | None, set[str]] = {
    None: {SessionState.ACTIVE},
    SessionState.ACTIVE: {SessionState.TERMINATED},
    SessionState.TERMINATED: set(),
}


class InvalidSessionTransition(Exception):
    """Raised on an attempt to move the FSM along an edge that doesn't exist."""


def can_transition(current: str | None, target: str) -> bool:
    return target in _ALLOWED.get(current, set())


def assert_transition(current: str | None, target: str) -> None:
    if not can_transition(current, target):
        raise InvalidSessionTransition(
            f"cannot move session from {current!r} to {target!r}"
        )
