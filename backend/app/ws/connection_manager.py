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

    async def close(
        self, session_id: str, *, code: int = 1000, reason: str = ""
    ) -> bool:
        """Force-close a session's socket if we hold it. Returns True if we did."""
        websocket = self._connections.get(session_id)
        if websocket is None:
            return False
        try:
            await websocket.close(code=code, reason=reason)
        except Exception:  # noqa: BLE001 - socket may already be gone
            logger.debug("close() on already-dead socket for session %s", session_id)
        finally:
            self._connections.pop(session_id, None)
        return True


# Process-wide singleton.
manager = ConnectionManager()
