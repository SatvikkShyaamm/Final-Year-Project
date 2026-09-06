"""
Placeholder for Module 9 — Attack Simulation.

Will implement controlled endpoints (simulate IP change, VPN, unknown
device, large download, abnormal requests, failed logins, forced session
termination) that call into the REAL Module 5/6/7 logic rather than just
changing text in the UI, per the project's explicit requirement.
"""
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

router = APIRouter()

_NOT_IMPLEMENTED = JSONResponse(
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    content={"detail": "Not implemented yet — planned for Module 9 (Attack Simulation)."},
)


@router.post("/simulate/{event_type}", tags=["simulation"])
def simulate_event(event_type: str):
    return _NOT_IMPLEMENTED
