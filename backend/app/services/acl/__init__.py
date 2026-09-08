"""
services/acl/ -> Module 4: Dynamic ACL Management (the base paper's L-PEP role).

  fsm.py      ACL rule state machine (PENDING -> ACTIVE -> REMOVING -> REMOVED)
  store.py    Redis task queue + ref-counts + receipts + kernel mirror
  enforcer.py ipset vs simulated kernel-touching backends
  worker.py   the L-PEP loop that consumes the queue and enforces
  service.py  control-plane: create/remove rule rows + enqueue tasks; reads
  wiring.py   registers request/remove on the session open/close hooks

Importing this package wires the session hooks (via wiring.py), so a session
opening attaches an ACL rule and a session closing removes it with no code in
the session layer knowing ACL exists.
"""
from app.services.acl.service import (
    acl_status_map,
    average_latencies,
    count_active,
    get_rule,
    get_rule_for_session,
    list_rules,
    remove_acl_for_session,
    request_acl_for_session,
)
from app.services.acl.worker import drain_queue, process_task, run_worker
from app.services.acl import wiring as _wiring  # noqa: F401  (registers hooks)

__all__ = [
    "acl_status_map",
    "average_latencies",
    "count_active",
    "get_rule",
    "get_rule_for_session",
    "list_rules",
    "remove_acl_for_session",
    "request_acl_for_session",
    "drain_queue",
    "process_task",
    "run_worker",
]
