r"""
Module 10 -- Performance Test Script
Continuous Zero Trust Access Control Project

WHAT THIS MEASURES
-------------------
Under increasing concurrent load, how fast the real backend:
  1. registers a brand-new user and returns a usable access token
  2. opens that user's session WebSocket and gets back `session.established`
  3. activates the session's Dynamic ACL rule (Module 4's async L-PEP worker)
  4. terminates the session (admin call)
  5. removes/revokes that session's ACL rule

This deliberately bypasses Adaptive MFA (Module 6): it uses the access token
returned directly by POST /auth/register. Registration is NOT MFA-gated by
design (see Project status.md, sections 3 and 12) -- you already proved the
credentials in that same request. That lets this script generate real,
concurrent Session + ACL + Trust Score load without needing to solve an
emailed one-time code for dozens of synthetic throwaway accounts.

It does NOT measure the login/MFA step itself, and does not need
MFA_ENABLED=false -- registration was never subject to that gate either way.

WHAT YOU NEED
-------------
  - The backend actually running (docker compose up, or uvicorn directly)
    and reachable at --base-url / --ws-url (defaults assume localhost:8000).
  - A real ADMIN access token, to list ACL rules and terminate sessions.
    Quickest way to get one:
      1. Log in to the dashboard as an admin in your browser.
      2. Open DevTools -> Application (Chrome) / Storage (Firefox) ->
         Session Storage -> the site's origin.
      3. Copy the token value stored under the key tokenStore.ts uses
         (frontend/src/auth/tokenStore.ts) -- it is a long JWT string.
      4. Pass it via --admin-token "<that value>".
    (It's sessionStorage, not localStorage, since the section-10 hardening
    pass -- see Project status.md -- so it won't survive closing the tab;
    grab a fresh one if the script reports 401s partway through.)

HOW TO RUN (Windows, from the project root, using the backend's own venv
which already has httpx installed per requirements.txt):

    backend\.venv\Scripts\python.exe scripts\module10_performance_test.py ^
        --admin-token "PASTE_YOUR_ADMIN_JWT_HERE" ^
        --levels 1,5,10,25

Results print to the console as a summary table AND get written in full to
--output (default: module10_perf_results.json) for the Module 10 report.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
import uuid
from dataclasses import dataclass, field

import httpx
import websockets


# --------------------------------------------------------------------------
# Small stats helpers (no extra dependencies beyond the stdlib).
# --------------------------------------------------------------------------

def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(p * (len(s) - 1)))))
    return s[k]


def summarize(values: list[float]) -> dict:
    if not values:
        return {"count": 0, "avg": None, "p50": None, "p95": None, "max": None}
    return {
        "count": len(values),
        "avg": round(statistics.fmean(values), 1),
        "p50": round(percentile(values, 0.50), 1),
        "p95": round(percentile(values, 0.95), 1),
        "max": round(max(values), 1),
    }


@dataclass
class LevelResult:
    level: int
    register_ms: list[float] = field(default_factory=list)
    session_establish_ms: list[float] = field(default_factory=list)
    terminate_ms: list[float] = field(default_factory=list)
    acl_authorization_ms: list[float] = field(default_factory=list)
    acl_revocation_ms: list[float] = field(default_factory=list)
    succeeded: int = 0
    failed: int = 0
    errors: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# One virtual user's lifecycle: register -> open session -> hold -> (caller
# terminates + measures ACL afterward, in bulk, across the whole level).
# --------------------------------------------------------------------------

async def register_user(
    client: httpx.AsyncClient, base_url: str, idx: int, tag: str, request_timeout: float
) -> tuple[str, float]:
    """POST /auth/register for one unique throwaway user.
    Returns (access_token, latency_ms). Raises on a non-2xx response."""
    unique = f"{tag}-{idx}-{uuid.uuid4().hex[:8]}"
    payload = {
        "username": unique,
        "email": f"{unique}@example.com",
        "password": "PerfTest!12345",
    }
    t0 = time.perf_counter()
    resp = await client.post(f"{base_url}/auth/register", json=payload, timeout=request_timeout)
    latency_ms = (time.perf_counter() - t0) * 1000
    if resp.status_code >= 400:
        # Surface the real validation error body instead of a bare status code,
        # so a 422 tells you exactly which field failed and why.
        raise RuntimeError(f"HTTP {resp.status_code} registering user {unique!r}: {resp.text}")
    data = resp.json()
    return data["access_token"], latency_ms


async def run_one_virtual_user(
    client: httpx.AsyncClient,
    base_url: str,
    ws_url: str,
    idx: int,
    tag: str,
    hold_seconds: float,
    result: LevelResult,
    session_ids: list[str],
    lock: asyncio.Lock,
    request_timeout: float,
) -> None:
    try:
        token, reg_ms = await register_user(client, base_url, idx, tag, request_timeout)
        result.register_ms.append(reg_ms)

        t0 = time.perf_counter()
        async with websockets.connect(f"{ws_url}/ws/session?token={token}", open_timeout=20) as ws:
            raw = await asyncio.wait_for(ws.recv(), timeout=20)
            establish_ms = (time.perf_counter() - t0) * 1000
            msg = json.loads(raw)
            session_id = msg.get("session_id")
            if not session_id:
                raise RuntimeError(f"no session_id in first WS message: {msg}")
            result.session_establish_ms.append(establish_ms)
            async with lock:
                session_ids.append(session_id)
            # Keep the socket open so the session stays genuinely ACTIVE while
            # the L-PEP worker drains the ACL "add" task for it, and so it's
            # still open when the batch termination step below runs.
            await asyncio.sleep(hold_seconds)
        result.succeeded += 1
    except Exception as exc:  # noqa: BLE001 -- one bad virtual user must not kill the run
        result.failed += 1
        result.errors.append(f"user {idx}: {type(exc).__name__}: {exc}")


# --------------------------------------------------------------------------
# Admin-side bulk operations for one concurrency level.
# --------------------------------------------------------------------------

async def fetch_acl_rules(
    client: httpx.AsyncClient, base_url: str, admin_token: str, include_removed: bool, request_timeout: float
) -> list[dict]:
    resp = await client.get(
        f"{base_url}/acl/rules",
        params={"include_removed": str(include_removed).lower()},
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=request_timeout,
    )
    resp.raise_for_status()
    return resp.json()["rules"]


async def terminate_sessions(
    client: httpx.AsyncClient,
    base_url: str,
    admin_token: str,
    session_ids: list[str],
    result: LevelResult,
    request_timeout: float,
) -> None:
    async def _terminate_one(sid: str) -> None:
        t0 = time.perf_counter()
        try:
            resp = await client.delete(
                f"{base_url}/sessions/{sid}",
                headers={"Authorization": f"Bearer {admin_token}"},
                timeout=request_timeout,
            )
            latency_ms = (time.perf_counter() - t0) * 1000
            if resp.status_code < 400:
                result.terminate_ms.append(latency_ms)
            else:
                result.errors.append(f"terminate {sid}: HTTP {resp.status_code}")
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"terminate {sid}: {type(exc).__name__}: {exc}")

    await asyncio.gather(*(_terminate_one(sid) for sid in session_ids))


async def run_level(
    level: int,
    base_url: str,
    ws_url: str,
    admin_token: str,
    hold_seconds: float,
    settle_seconds: float,
    request_timeout: float,
) -> LevelResult:
    result = LevelResult(level=level)
    session_ids: list[str] = []
    lock = asyncio.Lock()
    tag = f"m10perf{int(time.time())}"

    async with httpx.AsyncClient() as client:
        # 1) Fan out: register + open a session for every virtual user at once.
        await asyncio.gather(
            *(
                run_one_virtual_user(
                    client, base_url, ws_url, i, tag, hold_seconds, result, session_ids, lock, request_timeout
                )
                for i in range(level)
            )
        )

        if not session_ids:
            return result  # every virtual user failed -- nothing left to measure

        # 2) Let the async L-PEP worker finish draining "add" tasks, then read
        #    each rule's own authorization_latency_ms (still not-removed here).
        await asyncio.sleep(settle_seconds)
        try:
            rules_before = await fetch_acl_rules(
                client, base_url, admin_token, include_removed=False, request_timeout=request_timeout
            )
            by_session = {r.get("session_id"): r for r in rules_before}
            for sid in session_ids:
                rule = by_session.get(sid)
                if rule and rule.get("authorization_latency_ms") is not None:
                    result.acl_authorization_ms.append(float(rule["authorization_latency_ms"]))
        except Exception as exc:  # noqa: BLE001 -- keep register/session data even if this read fails/times out
            result.errors.append(f"GET /acl/rules (pre-terminate) failed: {type(exc).__name__}: {exc}")

        # 3) Terminate every session (admin call) and time each call.
        #    (terminate_sessions already isolates per-session failures internally.)
        try:
            await terminate_sessions(client, base_url, admin_token, session_ids, result, request_timeout)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"terminate_sessions batch failed: {type(exc).__name__}: {exc}")

        # 4) Let the worker drain the matching "remove" tasks, then read
        #    revocation_latency_ms back -- these rules are REMOVED now, so
        #    include_removed=True is required or the list would be empty.
        await asyncio.sleep(settle_seconds)
        try:
            rules_after = await fetch_acl_rules(
                client, base_url, admin_token, include_removed=True, request_timeout=request_timeout
            )
            by_session_after = {r.get("session_id"): r for r in rules_after}
            for sid in session_ids:
                rule = by_session_after.get(sid)
                if rule and rule.get("revocation_latency_ms") is not None:
                    result.acl_revocation_ms.append(float(rule["revocation_latency_ms"]))
        except Exception as exc:  # noqa: BLE001 -- keep everything already collected even if this read fails/times out
            result.errors.append(f"GET /acl/rules (post-terminate) failed: {type(exc).__name__}: {exc}")

    return result


# --------------------------------------------------------------------------
# Reporting.
# --------------------------------------------------------------------------

def print_and_collect(level_results: list[LevelResult]) -> dict:
    report = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "levels": []}
    col = lambda d: f"{d['avg']}/{d['p95']}" if d["count"] else "n/a"  # noqa: E731
    header = (
        f"{'Level':>6} | {'OK':>4} | {'Fail':>4} | {'Register avg/p95':>18} | "
        f"{'Session avg/p95':>17} | {'ACL auth avg/p95':>18} | "
        f"{'Terminate avg/p95':>19} | {'ACL revoke avg/p95':>20}"
    )
    print(header)
    print("-" * len(header))
    for r in level_results:
        reg, sess = summarize(r.register_ms), summarize(r.session_establish_ms)
        auth, term = summarize(r.acl_authorization_ms), summarize(r.terminate_ms)
        rev = summarize(r.acl_revocation_ms)
        print(
            f"{r.level:>6} | {r.succeeded:>4} | {r.failed:>4} | {col(reg):>18} | "
            f"{col(sess):>17} | {col(auth):>18} | {col(term):>19} | {col(rev):>20}"
        )
        report["levels"].append(
            {
                "level": r.level,
                "succeeded": r.succeeded,
                "failed": r.failed,
                "errors": r.errors[:10],
                "register_ms": reg,
                "session_establish_ms": sess,
                "acl_authorization_ms": auth,
                "terminate_ms": term,
                "acl_revocation_ms": rev,
            }
        )
    print("\n(all times in milliseconds; 'avg/p95' = mean / 95th percentile)")
    return report


async def main_async(args: argparse.Namespace) -> int:
    levels = [int(x) for x in args.levels.split(",") if x.strip()]
    level_results: list[LevelResult] = []
    for level in levels:
        print(f"\n--- Running concurrency level: {level} virtual user(s) ---")
        try:
            result = await run_level(
                level,
                args.base_url,
                args.ws_url,
                args.admin_token,
                args.hold_seconds,
                args.settle_seconds,
                args.request_timeout,
            )
        except Exception as exc:  # noqa: BLE001 -- one bad level must not lose results from earlier levels
            print(f"  LEVEL {level} FAILED ENTIRELY: {type(exc).__name__}: {exc}")
            result = LevelResult(level=level)
            result.failed = level
            result.errors.append(f"level failed entirely: {type(exc).__name__}: {exc}")
        level_results.append(result)
        if result.errors:
            print(f"  ({len(result.errors)} error(s) at this level -- first: {result.errors[0]})")

    print("\n=== Module 10 Performance Test -- Summary ===")
    report = print_and_collect(level_results)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\nFull results written to {args.output}")
    print("Paste the summary table above into docs/module-10-testing-evaluation.md.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Module 10 performance test for the ZTSAACM project.")
    parser.add_argument("--base-url", default="http://localhost:8000/api/v1", help="Backend REST base URL")
    parser.add_argument("--ws-url", default="ws://localhost:8000/api/v1", help="Backend WebSocket base URL")
    parser.add_argument("--admin-token", required=True, help="A real admin access token -- see module docstring")
    parser.add_argument("--levels", default="1,5,10,25", help="Comma-separated concurrent-user counts to test")
    parser.add_argument(
        "--hold-seconds", type=float, default=2.0,
        help="How long each session stays open before the batch termination step",
    )
    parser.add_argument(
        "--settle-seconds", type=float, default=1.5,
        help="Pause for the async ACL worker to drain its queue before reading latency fields back",
    )
    parser.add_argument(
        "--request-timeout", type=float, default=60.0,
        help="Per-HTTP-request timeout in seconds (raise this if you see ReadTimeout errors under heavier load)",
    )
    parser.add_argument("--output", default="module10_perf_results.json", help="Where to write the full JSON results")
    args = parser.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
