"""
Placeholder for Module 3 — Session Lifecycle.

Will implement the WebSocket session endpoint (the base paper's SS-PDP
signaling channel: session_open / session_close driving the S1->S2->S3
FSM transitions) plus REST endpoints to list/inspect active sessions.
"""
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

router = APIRouter()

_NOT_IMPLEMENTED = JSONResponse(
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    content={"detail": "Not implemented yet — planned for Module 3 (Session Lifecycle)."},
)


@router.get("/sessions", tags=["sessions"])
def list_sessions():
    return _NOT_IMPLEMENTED


@router.delete("/sessions/{session_id}", tags=["sessions"])
def terminate_session(session_id: str):
    return _NOT_IMPLEMENTED


# NOTE: the actual WebSocket endpoint (e.g. @router.websocket("/ws/session"))
# is added in Module 3, backed by app/ws/connection_manager.py.
