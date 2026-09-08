"""
Run the L-PEP worker as its own process (base paper's data plane):

    python -m app.lpep

Use this when you want the enforcement plane physically separated from the
control plane, as the paper describes — typically on a Linux host with
``ipset`` and NET_ADMIN. In that setup also set ``L_PEP_WORKER_ENABLED=false``
on the backend so the in-process worker doesn't double-consume the queue.

It shares the exact same code path as the in-process worker
(``app.services.acl.worker.run_worker``); only the hosting differs.
"""
from __future__ import annotations

import asyncio
import signal

from app.core.logging import configure_logging, get_logger
from app.services.acl.enforcer import get_enforcer
from app.services.acl.worker import run_worker

logger = get_logger(__name__)


async def _main() -> None:
    configure_logging()
    stop = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # Windows
            pass

    logger.info("standalone L-PEP starting (enforcement=%s)", get_enforcer().name)
    await run_worker(stop)


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
