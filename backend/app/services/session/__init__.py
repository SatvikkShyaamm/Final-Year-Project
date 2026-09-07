"""
services/session/ -> Module 3: session lifecycle.

  fsm.py      the ZTSAACM S1->S2->S3 state machine + transition guard
  store.py    Redis index of active sessions + session event pub/sub
  service.py  orchestration over Postgres (source of truth) + store + fsm

The WebSocket endpoint (app/api/v1/endpoints/sessions.py), the /auth/logout
handler, and the background sweeper (app/main.py) are the only callers.
"""
from app.services.session.fsm import (
    InvalidSessionTransition,
    assert_transition,
    can_transition,
)
from app.services.session.service import (
    count_active,
    create_session,
    get_current_session_for_user,
    get_session,
    list_sessions,
    set_ws_connected,
    sweep_expired_sessions,
    terminate_session,
    terminate_user_sessions,
    touch_session,
)

__all__ = [
    "InvalidSessionTransition",
    "assert_transition",
    "can_transition",
    "count_active",
    "create_session",
    "get_current_session_for_user",
    "get_session",
    "list_sessions",
    "set_ws_connected",
    "sweep_expired_sessions",
    "terminate_session",
    "terminate_user_sessions",
    "touch_session",
]
