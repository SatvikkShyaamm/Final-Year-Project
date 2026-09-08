"""
Session lifecycle hook registry — Module 3 infrastructure, consumed by Module 4+.

The session layer must not import the ACL layer (the project's architectural
rule: keep Session Management and ACL Enforcement separate; downstream modules
act on session events, the session layer doesn't know about them). So instead
``create_session`` / ``terminate_session`` call ``emit_*`` here, and Module 4
registers callbacks with ``@on_session_opened`` / ``@on_session_closed`` at
import time. Dependency direction stays one-way: acl -> session.

Every ``session.opened`` funnels through ``create_session`` and every close
funnels through ``terminate_session``, so a single hook here covers all four
termination paths (ws drop / logout / admin / sweep).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from sqlalchemy.orm import Session as DbSession

from app.core.logging import get_logger

if TYPE_CHECKING:  # avoid a runtime import cycle
    from app.models.session import Session as SessionModel

logger = get_logger(__name__)

OpenedHook = Callable[[DbSession, "SessionModel"], None]
ClosedHook = Callable[[DbSession, str, int, str], None]

_opened_hooks: list[OpenedHook] = []
_closed_hooks: list[ClosedHook] = []


def on_session_opened(fn: OpenedHook) -> OpenedHook:
    _opened_hooks.append(fn)
    return fn


def on_session_closed(fn: ClosedHook) -> ClosedHook:
    _closed_hooks.append(fn)
    return fn


def emit_session_opened(db: DbSession, session: "SessionModel") -> None:
    for fn in list(_opened_hooks):
        try:
            fn(db, session)
        except Exception:  # noqa: BLE001 - a hook failure must not fail the session
            logger.exception("session_opened hook %r failed", getattr(fn, "__name__", fn))


def emit_session_closed(
    db: DbSession, session_id: str, user_id: int, reason: str
) -> None:
    for fn in list(_closed_hooks):
        try:
            fn(db, session_id, user_id, reason)
        except Exception:  # noqa: BLE001
            logger.exception("session_closed hook %r failed", getattr(fn, "__name__", fn))


def clear_hooks() -> None:
    """Test helper — drop all registered hooks."""
    _opened_hooks.clear()
    _closed_hooks.clear()
