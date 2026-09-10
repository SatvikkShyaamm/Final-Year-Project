"""
Registers the token-revocation reaction to session termination.

Imported for its side effects by app/services/auth/__init__.py, same pattern
as Module 4's ACL wiring and Module 5's trust-score wiring: the session layer
never imports auth/revocation; it only emits a ``session_closed`` event that
this hook consumes. Dependency direction: auth -> session (never the reverse).

Unlike ACL/trust-score, this hook doesn't need any auth *business logic* —
just the `token_jti` / `token_exp` that were stamped onto the session row when
it opened (see app.services.session.service.create_session), so it reads the
session row directly rather than calling into services.auth.service.

Only revokes for a "terminated for cause" reason — the same set the frontend
already treats as a server-driven end worth forcing a logout for (see
docs/architecture.md and frontend/src/session/SessionProvider.tsx's
`onTerminated`): LOGOUT, ADMIN_TERMINATED, IDLE_TIMEOUT, MAX_LIFETIME, and
(reserved) RISK_REVOKED. An ordinary WEBSOCKET_DISCONNECT — a closed tab or a
page refresh — is deliberately excluded: per Project status.md sections 4/6b
and docs/architecture.md, a refresh while the session is still active is
*meant* to reopen a fresh session with the same still-valid token, and every
other module (and the test suite) relies on that. Revoking on every
disconnect would silently break that documented behaviour and any legitimate
multi-session use of one token — it would also make the token single-use in a
way nothing in this project ever specified.
"""
from __future__ import annotations

from sqlalchemy.orm import Session as DbSession

from app.models.session import Session as SessionModel
from app.models.session import TerminationReason
from app.services.auth.revocation import revoke_access_token
from app.services.session.hooks import on_session_closed

_WIRED = False

_REVOKE_ON_REASONS = frozenset(
    {
        TerminationReason.LOGOUT,
        TerminationReason.ADMIN_TERMINATED,
        TerminationReason.IDLE_TIMEOUT,
        TerminationReason.MAX_LIFETIME,
        TerminationReason.RISK_REVOKED,
    }
)


def wire() -> None:
    """Idempotent — safe to call more than once."""
    global _WIRED
    if _WIRED:
        return

    @on_session_closed
    def _revoke_token_on_session_closed(
        db: DbSession, session_id: str, user_id: int, reason: str
    ) -> None:
        if reason not in _REVOKE_ON_REASONS:
            return
        session = db.get(SessionModel, session_id)
        if session is None:
            return
        revoke_access_token(session.token_jti, session.token_exp)

    _WIRED = True


wire()
