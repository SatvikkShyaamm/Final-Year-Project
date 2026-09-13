"""
FastAPI application entrypoint.

Run directly with:  uvicorn app.main:app --reload --port 8000
(from the backend/ directory, with the virtualenv from requirements.txt active)
"""
import asyncio
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.database import SessionLocal
from app.core.logging import configure_logging, get_logger
from app.models.mfa import MFAChallengeReason
from app.models.session import Session as SessionModel
from app.models.session import SessionState, TerminationReason
from app.services import mfa as mfa_service
from app.services import session as session_service
from app.services.acl.worker import run_worker as run_acl_worker
from app.ws.connection_manager import manager

settings = get_settings()
configure_logging()
logger = get_logger(__name__)


async def _session_sweeper() -> None:
    """
    Periodically close sessions whose signalling socket has gone quiet past the
    idle timeout, or that have exceeded the max lifetime (Module 3). The normal
    close path is the WebSocket dropping; this only catches half-open/zombie
    sockets and enforces the hard lifetime cap.

    Also (Module 7): expires any still-PENDING MFA challenge past its
    `expires_at`, and for a `risk_retrigger` one that's scoped to a still-ACTIVE
    session, revokes that session too -- an unanswered re-verification request
    is a failed one (fail safe, not fail open), and nothing else would ever
    notice if the user simply never responds.
    """
    interval = max(5, settings.session_sweep_interval_seconds)
    while True:
        await asyncio.sleep(interval)
        try:
            db = SessionLocal()
            try:
                closed = session_service.sweep_expired_sessions(db)
                # Look up the reason the sweeper actually recorded for each
                # session (idle_timeout vs max_lifetime) so the client gets an
                # accurate session.terminated message -- sent before the close
                # frame, same as admin-terminate and logout, so the socket
                # closing doesn't race the frontend into treating this as an
                # ordinary drop and reconnecting into a brand-new session.
                reasons = {
                    row.id: row.termination_reason
                    for row in db.query(SessionModel).filter(
                        SessionModel.id.in_(closed)
                    )
                } if closed else {}

                expired_challenges = mfa_service.expire_overdue_challenges(db)
                revoked: list[str] = []
                for challenge in expired_challenges:
                    if challenge.reason != MFAChallengeReason.RISK_RETRIGGER:
                        continue
                    if not challenge.session_id:
                        continue
                    session_row = session_service.get_session(db, challenge.session_id)
                    if session_row is None or session_row.state != SessionState.ACTIVE:
                        continue
                    session_service.terminate_session(
                        db, challenge.session_id, reason=TerminationReason.RISK_REVOKED
                    )
                    revoked.append(challenge.session_id)
            finally:
                db.close()
            for session_id in closed:
                reason = reasons.get(session_id) or "session_timeout"
                await manager.close(
                    session_id,
                    code=1000,
                    reason="session timeout",
                    message={"type": "session.terminated", "reason": reason},
                )
            for session_id in revoked:
                await manager.close(
                    session_id,
                    code=1000,
                    reason="risk_revoked",
                    message={"type": "session.terminated", "reason": TerminationReason.RISK_REVOKED},
                )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a transient DB blip must not kill the loop
            logger.warning("session sweeper iteration failed", exc_info=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("%s starting up in '%s' mode", settings.project_name, settings.environment)
    tasks: list[asyncio.Task] = [asyncio.create_task(_session_sweeper())]

    acl_stop = asyncio.Event()
    if settings.l_pep_worker_enabled:
        # In-process L-PEP (base paper's data plane) for the single-container
        # dev/demo setup. Set L_PEP_WORKER_ENABLED=false when running the
        # standalone infra/l-pep worker instead.
        tasks.append(asyncio.create_task(run_acl_worker(acl_stop)))

    try:
        yield
    finally:
        acl_stop.set()
        for task in tasks:
            task.cancel()
        for task in tasks:
            with suppress(asyncio.CancelledError):
                await task
        logger.info("%s shutting down", settings.project_name)


app = FastAPI(
    title=settings.project_name,
    description=(
        "Zero Trust Session-Aware Access Control system, extended with "
        "Trust Score, Adaptive MFA, and Continuous Trust Evaluation."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")


@app.get("/", tags=["system"])
def root() -> dict:
    return {
        "project": settings.project_name,
        "status": "running",
        "docs": "/docs",
        "api_prefix": "/api/v1",
    }
