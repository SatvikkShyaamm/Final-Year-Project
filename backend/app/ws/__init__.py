"""
WebSocket layer package — the SS-PDP signalling channel described in the
base paper. Module 3 adds:

  connection_manager.py -> process-wide {session_id: WebSocket} table
                            (mirrors the paper's connection-manager class) so
                            the control plane can force a session's socket shut.
  auth.py               -> ?token= handshake verification, reusing the Module 2
                            JWT primitives.

The socket handler itself lives with its route in
app/api/v1/endpoints/sessions.py; the FSM + persistence it drives live in
app/services/session/.
"""
