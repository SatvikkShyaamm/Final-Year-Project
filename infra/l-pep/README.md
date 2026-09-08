# infra/l-pep — Lightweight Policy Enforcement Point (Module 4)

The base paper's **data plane**: the process that turns "session open / close"
into kernel-level network ACL changes (`ipset add` / `ipset del` against the
`ztsaacm_allowed` / `ztsaacm_allowed_v6` sets), driven by tasks the control
plane (the FastAPI backend) pushes onto a Redis queue.

## Two ways to run it

The worker code is `backend/app/services/acl/worker.py`. It runs in one of two
places — the logic is identical:

1. **In-process (default).** The backend runs the worker as a lifespan task.
   `L_PEP_WORKER_ENABLED=true` (the default). This is what `docker compose up`
   gives you. On a machine without `ipset` (any dev box, the Docker backend
   container, CI) the worker's enforcer auto-falls-back to *simulated* mode:
   the allow-list is recorded in Redis (`ztsaacm:acl:kernel:*`) and the whole
   control-plane mechanism — rule records, ref-counting, task queue, receipts,
   automatic teardown, latency measurement — still runs and is visible in the
   dashboard's ACL Monitor.

2. **Standalone (faithful to the paper).** On a Linux host with `ipset` and
   `NET_ADMIN`:

   ```bash
   ./infra/l-pep/setup-ipset.sh          # create the sets + iptables rules (once)
   cd backend
   ACL_ENFORCEMENT_BACKEND=ipset python -m app.lpep
   ```

   and set `L_PEP_WORKER_ENABLED=false` on the backend so the queue isn't
   double-consumed. `docker compose --profile lpep up` wires this as a
   separate `l-pep` container.

## Redis keys it uses

| key                              | role                                        |
|----------------------------------|---------------------------------------------|
| `ztsaacm:acl:tasks`              | task queue (LPUSH by backend, BRPOP by L-PEP)|
| `ztsaacm:acl:refcount:{ip}`      | one kernel entry per IP regardless of #sessions |
| `ztsaacm:acl:receipt:{task_id}`  | completion receipt pub/sub (latency analysis) |
| `ztsaacm:acl:kernel:{set}`       | simulated-mode allow-list mirror            |
| `ztsaacm:events:acl`             | acl.requested / applied / removed events (Module 8) |

eBPF is a possible future enhancement and is deliberately **not** required
here — `ipset` + `iptables` is the initial, manageable implementation.
