"""
WebSocket layer package — the SS-PDP signaling channel described in the
base paper. Module 3 will add:

  connection_manager.py -> in-memory {user_id: (WebSocket, client_ip)} table
                            (mirrors the paper's connection-manager class),
                            plus the session_open / session_close handlers
                            that drive the FSM and emit ACL tasks.

Left empty in Module 1 because there is no session concept to manage yet.
"""
