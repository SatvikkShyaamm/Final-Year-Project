"""
Aggregates all v1 endpoint routers into one APIRouter mounted by main.py.

Adding a new module's endpoints later means: create
app/api/v1/endpoints/<module>.py, then include its router here. Nothing
else in main.py needs to change.
"""
from fastapi import APIRouter

from app.api.v1.endpoints import (
    acl,
    auth,
    dashboard,
    health,
    mfa,
    sessions,
    simulation,
    trust,
)

api_router = APIRouter()

api_router.include_router(health.router)          # Module 1
api_router.include_router(auth.router)             # Module 2
api_router.include_router(sessions.router)          # Module 3
api_router.include_router(acl.router)               # Module 4
api_router.include_router(trust.router)             # Module 5
api_router.include_router(mfa.router)               # Module 6
api_router.include_router(dashboard.router)         # Module 8
api_router.include_router(simulation.router)        # Module 9
