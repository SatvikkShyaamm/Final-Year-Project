"""
Registers Module 5's reaction to session creation, and (2026-09-15) Module 7
Section 18's reaction to session close.

Imported for its side effects by app/services/trust_score/__init__.py. Same
pattern as Module 4's ACL wiring: the session layer never imports trust_score;
it only emits ``session_opened`` / ``session_closed`` events that these hooks
consume. Dependency direction: trust_score -> session.
"""
from __future__ import annotations

from sqlalchemy.orm import Session as DbSession

from app.models.session import Session as SessionModel
from app.services.session.hooks import on_session_closed, on_session_opened
from app.services.trust_score.service import evaluate_for_session

_WIRED = False


def wire() -> None:
    global _WIRED
    if _WIRED:
        return

    @on_session_opened
    def _trust_on_session_opened(db: DbSession, session: SessionModel) -> None:
        evaluate_for_session(db, session)

    # Section 18 (2026-09-15): the heartbeat detector's per-session Redis
    # state ("last observed" IP/UA + the request-rate counter) is scoped to
    # the session's own lifetime, mirroring the ACL ref-count pattern
    # (app.services.acl.wiring) -- clear it the instant the session actually
    # ends rather than relying solely on its TTL safety net.
    #
    # Imported lazily, inside the hook, rather than at module level: this
    # wire() runs from trust_score/__init__.py's own top-level execution, and
    # heartbeat.py imports app.services.trust_score.continuous, which in turn
    # imports app.services.mfa / app.services.session -- importing all of
    # that eagerly, mid-way through trust_score's own package init, is an
    # avoidable circular-import risk for no benefit, since this hook is only
    # ever invoked long after application startup has finished.
    @on_session_closed
    def _heartbeat_on_session_closed(
        db: DbSession, session_id: str, user_id: int, reason: str
    ) -> None:
        from app.services.trust_score import heartbeat as heartbeat_service

        heartbeat_service.clear_session_state(session_id)

    _WIRED = True


wire()
