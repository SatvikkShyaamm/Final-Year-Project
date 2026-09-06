"""
Placeholder for Module 4 — Dynamic ACL Management.

Will implement ACL creation/removal bound to session lifecycle (the base
paper's L-PEP role: ipset add/del keyed by client IP with a reference count),
plus a REST view of current ACL rules for the dashboard's ACL Monitor.
"""
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

router = APIRouter()

_NOT_IMPLEMENTED = JSONResponse(
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    content={"detail": "Not implemented yet — planned for Module 4 (Dynamic ACL Management)."},
)


@router.get("/acl/rules", tags=["acl"])
def list_acl_rules():
    return _NOT_IMPLEMENTED
