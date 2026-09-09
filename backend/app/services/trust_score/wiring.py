"""
Registers Module 5's reaction to session creation.

Imported for its side effects by app/services/trust_score/__init__.py. Same
pattern as Module 4's ACL wiring: the session layer never imports trust_score;
it only emits a ``session_opened`` event that this hook consumes. Dependency
direction: trust_score -> session.
"""
from __future__ import annotations

from sqlalchemy.orm import Session as DbSession

from app.models.session import Session as SessionModel
from app.services.session.hooks import on_session_opened
from app.services.trust_score.service import evaluate_for_session

_WIRED = False


def wire() -> None:
    global _WIRED
    if _WIRED:
        return

    @on_session_opened
    def _trust_on_session_opened(db: DbSession, session: SessionModel) -> None:
        evaluate_for_session(db, session)

    _WIRED = True


wire()
