"""
In-memory registry of live session WebSockets — Module 3.

Mirrors the base paper's connection-manager class: it maps a session id to its
open signalling socket so the control plane can force a close (admin
termination, idle sweep, and from Module 7, risk revocation).

Scope note: this table lives in one process. A multi-worker / multi-replica
deployment would additionally publish a "close this session" message on Redis
so every worker can act on its own local sockets. That fan-out is deliberately
out of scope for Module 3 (single backend container); the Redis event channel
in services/session/store.py is where it would hook in.
"""
from __future__ import annotations

from typing import Any

from starlette.websockets import WebSocket

from app.core.logging import get_logger

logger = get_logger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}

    def register(self, session_id: str, websocket: WebSocket) -> None:
        self._connections[session_id] = websocket

    def unregister(self, session_id: str) -> None:
        self._connections.pop(session_id, None)

    def is_connected(self, session_id: str) -> bool:
        return session_id in self._connections

    def count(self) -> int:
        return len(self._connections)

    def session_ids(self) -> set[str]:
        return set(self._connections)

    async def send(self, session_id: str, message: dict[str, Any]) -> bool:
        """
        Push a live message down a session's socket WITHOUT closing it.

        The additive counterpart to close()'s pre-close send: Module 7 uses
        this to notify an ACTIVE session's client that continuous
        re-evaluation now requires a fresh emailed code
        (`trust.reverify_required`) or that a pending one just succeeded
        (`trust.reverified`) -- neither of those should end the session by
        itself. Best-effort, same policy as everywhere else this codebase
        touches an optional live channel: a momentarily-absent or
        already-dead socket is not an error, just a no-op.
        """
        websocket = self._connections.get(session_id)
        if websocket is None:
            return False
        try:
            await websocket.send_json(message)
            return True
        except Exception:  # noqa: BLE001 - socket may already be gone
            logger.debug("send() failed for session %s", session_id)
            return False

    async def close(
        self,
        session_id: str,
        *,
        code: int = 1000,
        reason: str = "",
        message: dict[str, Any] | None = None,
    ) -> bool:
        """
        Force-close a session's socket if we hold it. Returns True if we did.

        If `message` is given, it is sent (best-effort, as JSON) *before* the
        close frame goes out. This is what lets a server-initiated termination
        (admin DELETE, idle/lifetime sweep) tell the client's SessionSocket
        "this was intentional, do not reconnect" via a `session.terminated`
        payload -- sending it after close() is too late: closing flips the
        connection's state to disconnected immediately, so a send attempted
        afterwards silently fails and the client sees an ordinary drop and
        auto-reconnects, opening a brand-new session right behind the one that
        was just terminated.
        """
        websocket = self._connections.get(session_id)
        if websocket is None:
            return False
        if message is not None:
            try:
                await websocket.send_json(message)
            except Exception:  # noqa: BLE001 - socket may already be gone
                logger.debug(
                    "pre-close send_json failed for session %s", session_id
                )
        try:
            await websocket.close(code=code, reason=reason)
        except Exception:  # noqa: BLE001 - socket may already be gone
            logger.debug("close() on already-dead socket for session %s", session_id)
        finally:
            self._connections.pop(session_id, None)
        return True


# Process-wide singleton.
manager = ConnectionManager()
