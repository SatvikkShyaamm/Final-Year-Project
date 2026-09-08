"""
ACL enforcement backends — Module 4 (the base paper's L-PEP action).

The distributed protocol around this (task queue, ref-counting, receipts,
session-bound rule records, automatic teardown) is always real. Only the final
step — actually touching the kernel allow-list — has two implementations:

  IpsetEnforcer      shells out to `ipset add -exist` / `ipset del -exist`
                     against the ztsaacm_allowed / _v6 sets. Needs a Linux host
                     with NET_ADMIN; this is what the standalone infra/l-pep
                     runs on the demo box.
  SimulatedEnforcer  records the allow-list in Redis (store.kernel_*). Used on
                     dev machines, in Docker Compose, and in CI where `ipset`
                     isn't available. NOT a UI fake — the whole control-plane
                     mechanism still runs and is observable.

`ACL_ENFORCEMENT_BACKEND=auto` (the default) probes for a working `ipset` and
falls back to simulation, logging which one it picked.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Protocol

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.acl import store

logger = get_logger(__name__)
settings = get_settings()

_CMD_TIMEOUT = 5


class Enforcer(Protocol):
    name: str

    def add(self, ipset_name: str, ip: str, *, ttl: int) -> tuple[bool, str | None]: ...

    def remove(self, ipset_name: str, ip: str) -> tuple[bool, str | None]: ...


def _run(cmd: list[str]) -> tuple[bool, str | None]:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd, capture_output=True, text=True, timeout=_CMD_TIMEOUT
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if proc.returncode == 0:
        return True, None
    return False, (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()[:256]


class SimulatedEnforcer:
    name = "simulated"

    def add(self, ipset_name: str, ip: str, *, ttl: int) -> tuple[bool, str | None]:
        store.kernel_add(ipset_name, ip, ttl=ttl)
        logger.info("acl[simulated] + %s -> %s (ttl=%s)", ip, ipset_name, ttl)
        return True, None

    def remove(self, ipset_name: str, ip: str) -> tuple[bool, str | None]:
        store.kernel_remove(ipset_name, ip)
        logger.info("acl[simulated] - %s <- %s", ip, ipset_name)
        return True, None


class IpsetEnforcer:
    name = "ipset"

    def add(self, ipset_name: str, ip: str, *, ttl: int) -> tuple[bool, str | None]:
        cmd = ["ipset", "add", "-exist", ipset_name, ip]
        if ttl > 0:
            cmd += ["timeout", str(ttl)]
        ok, err = _run(cmd)
        if not ok:
            logger.error("acl[ipset] add %s -> %s failed: %s", ip, ipset_name, err)
        return ok, err

    def remove(self, ipset_name: str, ip: str) -> tuple[bool, str | None]:
        ok, err = _run(["ipset", "del", "-exist", ipset_name, ip])
        if not ok:
            logger.error("acl[ipset] del %s <- %s failed: %s", ip, ipset_name, err)
        return ok, err


def _ipset_available() -> bool:
    if shutil.which("ipset") is None:
        return False
    return _run(["ipset", "list", "-n"])[0]


_enforcer: Enforcer | None = None


def get_enforcer() -> Enforcer:
    """Cached per process. Call reset_enforcer() in tests to re-select."""
    global _enforcer
    if _enforcer is not None:
        return _enforcer

    mode = settings.acl_enforcement_backend.lower()
    if mode == "simulated":
        _enforcer = SimulatedEnforcer()
    elif mode == "ipset":
        _enforcer = IpsetEnforcer()
    elif _ipset_available():
        logger.info("ACL enforcement backend: ipset (kernel)")
        _enforcer = IpsetEnforcer()
    else:
        logger.info("ACL enforcement backend: simulated (ipset unavailable)")
        _enforcer = SimulatedEnforcer()
    return _enforcer


def reset_enforcer() -> None:
    global _enforcer
    _enforcer = None
