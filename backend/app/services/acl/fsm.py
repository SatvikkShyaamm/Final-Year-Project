"""
ACL rule state machine — Module 4.

    PENDING  --applied-->        ACTIVE
    PENDING  --error-->          FAILED
    ACTIVE   --revoke requested--> REMOVING
    REMOVING --applied-->        REMOVED
    (any live state) --error-->  FAILED

Mirrors the enforcement task's progress. The transition guard keeps the L-PEP
worker from, e.g., re-activating a rule that is already being torn down.
"""
from __future__ import annotations

from app.models.acl import ACLState

_ALLOWED: dict[str, set[str]] = {
    ACLState.PENDING: {ACLState.ACTIVE, ACLState.REMOVING, ACLState.FAILED},
    ACLState.ACTIVE: {ACLState.REMOVING, ACLState.FAILED},
    ACLState.REMOVING: {ACLState.REMOVED, ACLState.FAILED},
    ACLState.REMOVED: set(),
    ACLState.FAILED: {ACLState.REMOVING, ACLState.REMOVED},
}


class InvalidACLTransition(Exception):
    pass


def can_transition(current: str, target: str) -> bool:
    return target in _ALLOWED.get(current, set())


def assert_transition(current: str, target: str) -> None:
    if not can_transition(current, target):
        raise InvalidACLTransition(f"cannot move ACL rule from {current!r} to {target!r}")
