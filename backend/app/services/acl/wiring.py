"""
Registers Module 4's reactions to session lifecycle events.

Imported for its side effects by app/services/acl/__init__.py, so simply
importing the ACL package wires the hooks. Dependency direction: acl -> session
(never the reverse).
"""
from __future__ import annotations

from sqlalchemy.orm import Session as DbSession

from app.models.session import Session as SessionModel
from app.services.acl.service import remove_acl_for_session, request_acl_for_session
from app.services.session.hooks import on_session_closed, on_session_opened

_WIRED = False


def wire() -> None:
    """Idempotent — safe to call more than once."""
    global _WIRED
    if _WIRED:
        return

    @on_session_opened
    def _acl_on_session_opened(db: DbSession, session: SessionModel) -> None:
        request_acl_for_session(db, session)

    @on_session_closed
    def _acl_on_session_closed(
        db: DbSession, session_id: str, user_id: int, reason: str
    ) -> None:
        remove_acl_for_session(db, session_id, reason=reason)

    _WIRED = True


wire()
