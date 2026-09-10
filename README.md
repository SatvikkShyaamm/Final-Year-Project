# ZTSAACM Security Dashboard

A Zero Trust Session-Aware Access Control system (based on Chang & Xu's
ZTSAACM base paper) extended with Trust Score, Adaptive MFA, and
Continuous Trust Evaluation, presented through a SOC-style admin
dashboard. See `docs/architecture.md` and the project's Claude project
docs for full context before making architectural changes.

**Module status:** Modules 1-6 (Project Foundation, Authentication, Session
Lifecycle, Dynamic ACL, Trust Score Engine, Adaptive MFA) are implemented.
The core base-paper flow works end to end; every login runs a trust-score
risk decision and MEDIUM-risk logins are gated by TOTP MFA. Modules 7-9 are
still scaffolding — their endpoints exist as routes but honestly return
`501 Not Implemented`; nothing is mocked to look like it works. See
`Project status.md`.

## What actually works right now

- Backend (FastAPI) boots and serves `GET /api/v1/health`, which performs
  a **live** `SELECT 1` against Postgres and a **live** `PING` against
  Redis — it reports "unreachable" if either is actually down, it doesn't
  fake success.
- **Authentication (Module 2)** — real:
  - `POST /api/v1/auth/register` hashes the password with bcrypt, stores a
    `users` row, returns a signed JWT (no MFA gate — you just created and
    proved these credentials in the same request). The **first** account on a
    fresh DB becomes `admin`; the rest are `user`.
  - `POST /api/v1/auth/login` verifies credentials, then runs the Module 6
    risk decision (below).
  - `GET /api/v1/auth/me` validates the `Authorization: Bearer` token and
    returns the current user; bad/expired/forged tokens — and the
    `mfa_pending` token — get `401`.
  - `get_current_user` / `get_current_admin` dependencies in
    `app/api/deps.py` are the auth middleware every later module reuses.
- **Session Lifecycle (Module 3)** — real:
  - `WS /api/v1/ws/session?token=<jwt>` is the base paper's signalling
    channel: the socket opening creates a `sessions` row (FSM S1→S2), the
    socket closing terminates it (S2→S3). Ping/pong keeps it warm.
  - A session also ends on `POST /auth/logout` (now terminates the user's
    sessions server-side), on admin `DELETE /api/v1/sessions/{id}`, or via
    the idle/max-lifetime sweeper running in the app lifespan.
  - `GET /api/v1/sessions` (admin) is the dashboard's live feed;
    `GET /api/v1/sessions/current` is the caller's own session.
  - Redis holds the active-session index + a `session.opened`/`.closed`
    pub/sub channel for Module 8; Postgres stays the source of truth.
- **Dynamic ACL (Module 4)** — real:
  - A session opening fires a session hook that creates an `acl_rules` row
    and pushes an `add` task onto a Redis queue; the **L-PEP worker** pulls
    it, ref-counts the client IP, applies the kernel allow-list entry, and
    marks the rule `active` with a measured authorization latency. A session
    closing (any path) reverses it: `remove` task → rule `removed`, IP pulled
    from the allow-list, revocation latency recorded.
  - Ref-counting means two sessions from one IP share one kernel entry —
    closing one doesn't cut the other's access.
  - Enforcement backend is `ipset`/`iptables` on a Linux host
    (`infra/l-pep/`, `python -m app.lpep`) or **simulated** (allow-list
    mirrored in Redis) everywhere else — auto-detected. The whole
    control-plane mechanism is real either way; only the final syscall is
    swapped, and the dashboard reports which backend is live.
  - `GET /api/v1/acl/rules` + `GET /api/v1/acl/status` (admin) feed the ACL
    Monitor. ACL rules are not hand-editable — terminating a session removes
    its rule.
- **Trust Score Engine (Module 5)** — real, per the finalized Section-6 spec:
  - A session opening also fires a hook that computes a **static** trust
    score: `clamp(70 + Σ positive − Σ negative, 0, 100)` over the finalized
    factor table (known/unknown device, known IP / IP-changed, approved vs
    known-public VPN CIDR, ≥3 failed logins in 15 min, typical-hour vs
    off-hours). It's written to `sessions.trust_score` / `sessions.risk_level`
    with a per-factor breakdown in `trust_score_factors`.
  - First-ever login for a user has no history, so it lands at ~70 = MEDIUM →
    every user gets challenged on first login once Module 6 exists (a
    deliberate, approved Zero-Trust consequence).
  - Failed logins are counted in Redis (`ztsaacm:failed_logins:{user_id}`,
    15-min TTL), incremented from `POST /auth/login` failures.
  - Module 5 only *computes and reports* the score — turning MEDIUM/HIGH into
    "require MFA" / "block" is Module 6; in-session re-scoring is Module 7.
  - `GET /api/v1/trust-score/{session_id}` (score + breakdown),
    `/trust-score/user/{id}/history`, `/trust-score/config` (the live weight
    table) feed the Trust Score Monitoring page.
- **Adaptive MFA (Module 6)** — real, TOTP (RFC 6238):
  - `POST /api/v1/auth/login` computes a login-time trust score and applies
    the Section-6 bands: **LOW → access token**, **MEDIUM → MFA required**
    (returns a short-lived `mfa_pending` token + an `mfa_challenges` row),
    **HIGH → 403 blocked**. Because a first-ever login has no history it
    lands MEDIUM, so every user enrols an authenticator on first sign-in.
  - `POST /api/v1/mfa/verify` checks the 6-digit TOTP code (±1 step skew) and
    exchanges the `mfa_pending` token for a real access token. Expiry
    (5 min), retry limit (5 attempts) and success/failure are all enforced
    server-side; the `mfa_pending` token opens nothing else.
  - `POST /api/v1/mfa/challenge` is a step-up for an already-authenticated
    user (also Module 7's re-challenge hook); `GET /api/v1/mfa/challenges`
    (admin) is the dashboard's MFA events feed; `/mfa/config` shows the live
    policy.
  - In `ENVIRONMENT=development` the challenge response also carries the
    currently-valid code (`dev_code`) so the demo works without a phone —
    off in production.
- Frontend: a real login/register screen (with the **MFA step**: authenticator
  enrolment + 6-digit code + retry/expiry handling), a JWT-aware axios client
  (attaches the token, redirects to `/login` on `401`), an `AuthProvider`
  that rehydrates the session on refresh, route guards (`/admin` admin-only,
  `/portal` any logged-in user), a `SessionProvider` that opens the
  signalling WebSocket after login and reconnects on unexpected drops, a
  **live Live Sessions** table (auto-refreshing, per-row Terminate, real ACL
  + trust/risk columns), a **live ACL Monitor**, a **live Trust Score
  Monitoring** page (score meter, factor breakdown, per-user history chart,
  live weight table), a **live Security Alerts** page (the MFA events feed),
  and a session card with WebSocket + ACL + trust/risk status in the
  portal/header.
- The **System Status** page (`/admin/status`) still calls the real health
  endpoint and renders the real result.
- Every planned dashboard section (Live Sessions, Trust Score, Security
  Alerts, ACL Monitor, Analytics, Attack Simulation) has a real route and
  a clearly labeled "planned for Module N" placeholder — the navigation
  structure won't need to change as modules land.

## Stack

| Layer      | Technology                                             |
|------------|---------------------------------------------------------|
| Frontend   | React 19, TypeScript, Vite, Tailwind CSS v4, React Router, Recharts, Axios |
| Backend    | FastAPI, SQLAlchemy 2, Alembic, Pydantic Settings        |
| Auth       | JWT (PyJWT, HS256), bcrypt password hashing              |
| Sessions   | FastAPI WebSocket signalling + Redis active-session index |
| ACL        | Redis task queue + L-PEP worker → ipset/iptables (or simulated) |
| Trust Score| Weighted-factor engine (config-driven weights) + Redis failed-login counter |
| MFA        | TOTP (pyotp / RFC 6238), risk-band gated at login       |
| Database   | PostgreSQL 16                                            |
| Cache/Queue| Redis 7                                                  |
| Infra      | Docker, Docker Compose                                   |

## Folder structure

```
ztsaacm-dashboard/
├── docker-compose.yml         # postgres + redis + backend + frontend, wired together
├── .env.example                # root env vars, read by docker-compose.yml
├── docs/
│   └── architecture.md         # paper-to-code mapping, module boundaries
├── infra/
│   └── l-pep/                  # Module 4 L-PEP: setup-ipset.sh + how-to-run notes
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app + CORS + router mount + bg tasks
│   │   ├── core/                # config, DB session, Redis client, logging, security
│   │   ├── api/deps.py          # get_db + get_current_user/get_current_admin (Module 2)
│   │   ├── api/v1/endpoints/    # one file per module's REST endpoints
│   │   ├── models/              # ORM — user session acl trust_score (M5) mfa (M6)
│   │   ├── schemas/             # Pydantic schemas per module
│   │   ├── services/            # per module — auth/ session/ acl/ trust_score/ mfa/
│   │   ├── ws/                  # connection_manager.py + handshake auth.py (Module 3)
│   │   └── lpep/                # `python -m app.lpep` — standalone L-PEP worker (M4)
│   ├── alembic/versions/        # migrations — 0001 users … 0004 trust, 0005 mfa
│   ├── tests/                   # test_health / _auth / _sessions / _acl / _trust_score / _mfa
│   └── requirements.txt
└── frontend/
    └── src/
        ├── pages/admin/         # one page per dashboard section (Module 8)
        ├── auth/                # AuthProvider, ProtectedRoute, token store (M2)
        ├── session/            # SessionProvider, useSession (Module 3)
        ├── components/layout/   # Sidebar, AdminLayout
        ├── components/common/   # RiskBadge, PlaceholderCard, AclBadge (M4)
        ├── api/                 # axios client + typed API calls
        ├── ws/                  # SessionSocket client (Module 3)
        └── types/
```

## Running it — Docker Compose (recommended, matches how the team will actually deploy)

```bash
cp .env.example .env          # adjust POSTGRES_PASSWORD / JWT_SECRET_KEY etc.
docker compose up --build
```

- Frontend: http://localhost:5173
- Backend docs (Swagger UI): http://localhost:8000/docs
- Health check: http://localhost:8000/api/v1/health

`docker compose down -v` also drops the Postgres/Redis volumes if you want
a clean slate.

## Running it natively (no Docker) — useful for quick iteration

This is exactly how Module 1 was verified in this environment: both
services were run directly against a local Postgres/Redis, not just
inside Docker.

**Backend:**
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # edit if your local Postgres/Redis differ
alembic upgrade head          # from Module 2 on there is real schema (users table)
uvicorn app.main:app --reload --port 8000
```

> Use CPython 3.11 or 3.12 for a native run — that's what the Docker image
> (`python:3.11-slim`) uses and what the pinned `requirements.txt` has
> prebuilt wheels for. The Docker container runs `alembic upgrade head`
> automatically on start.

**Frontend** (separate terminal):
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

You need a local Postgres (`ztsaacm_db` database, matching the user from
your `.env`) and Redis reachable at the hosts/ports in `backend/.env` —
or just use Docker Compose for those two services only:
`docker compose up postgres redis`.

## Verifying it works

```bash
curl http://localhost:8000/api/v1/health
# {"status":"ok","dependencies":{"database":"connected","redis":"connected"}}
```

Then open http://localhost:5173/admin/status in a browser — it should
show the same result rendered live.

**Authentication + Adaptive MFA (Modules 2 + 6)** end to end:

```bash
# register (first account on a fresh DB is the admin). Register returns a
# usable access token directly — no MFA gate on registration.
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","email":"admin@example.com","password":"change-me-123"}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -s http://localhost:8000/api/v1/auth/me -H "Authorization: Bearer $TOKEN"

# LOGIN, by contrast, runs the risk decision. A first-ever login has no
# history -> MEDIUM -> MFA required:
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"change-me-123"}'
# -> {"mfa_required":true,"decision":"mfa","trust_score":70,"risk_level":"MEDIUM",
#     "mfa":{"challenge_id":"...","mfa_token":"<jwt>","enrollment":{"secret":"...",
#            "provisioning_uri":"otpauth://totp/..."},"dev_code":"123456"}}

# in ENVIRONMENT=development the response includes dev_code — the currently
# valid TOTP code — so you can complete it without an authenticator app:
curl -s -X POST http://localhost:8000/api/v1/mfa/verify \
  -H 'Content-Type: application/json' \
  -d '{"mfa_token":"<mfa_token from above>","code":"<dev_code from above>"}'
# -> {"access_token":"<real access token>","token_type":"bearer",...}
```

In the browser: http://localhost:5173/login → sign in → on first login the
MFA step appears (authenticator key + 6-digit code; dev shows the code) →
verify → the admin lands on the SOC dashboard. A HIGH-risk login (e.g. from a
known-VPN IP after several failed attempts) is refused outright.

**Session Lifecycle (Module 3)** end to end (reuse `$TOKEN` from above):

```bash
# open a session over the signalling WebSocket (needs a ws client, e.g. websocat)
websocat "ws://localhost:8000/api/v1/ws/session?token=$TOKEN"
# -> {"type":"session.established","session_id":"...","state":"active",...}

# while that socket is open, in another terminal:
curl -s http://localhost:8000/api/v1/sessions -H "Authorization: Bearer $TOKEN"
# -> {"sessions":[{...,"state":"active","ws_connected":true}], "active_count":1}

# close the websocket (Ctrl-C) or POST /auth/logout, then re-list:
# -> the session is now {"state":"terminated","termination_reason":"websocket_disconnect"|"logout"}
```

Or just use the browser: log in at `/login`, watch the "session connected"
indicator, open `/admin/sessions` as an admin to see the live table, and
click Terminate or Log out to watch the row flip to `terminated`.

**Dynamic ACL (Module 4)** end to end (with a session open, as above):

```bash
curl -s http://localhost:8000/api/v1/acl/rules -H "Authorization: Bearer $TOKEN"
# -> {"rules":[{...,"state":"active","client_ip":"...","enforcement":"simulated",
#     "authorization_latency_ms": 3}], "active_count":1, "enforcement_backend":"simulated"}

curl -s http://localhost:8000/api/v1/acl/status -H "Authorization: Bearer $TOKEN"
# -> {"enforcement_backend":"simulated","queue_depth":0,"active_rules":1,
#     "kernel_entries":{"ztsaacm_allowed":1,"ztsaacm_allowed_v6":0}}

# close the session's websocket -> the rule goes to state "removed" and the IP
# leaves kernel_entries, with a revocation_latency_ms recorded.
```

In the browser, `/admin/acl` shows the live rules table + enforcement-plane
stats; the Live Sessions table's ACL column and the portal's session card
both show the rule state. On a Linux host, `ACL_ENFORCEMENT_BACKEND=ipset`
plus `infra/l-pep/setup-ipset.sh` makes the allow-list a real kernel ipset.

**Trust Score (Module 5)** end to end (with a session open, as above):

```bash
# the score is on the WS establish message and on the session row
curl -s http://localhost:8000/api/v1/sessions -H "Authorization: Bearer $TOKEN"
# -> {"sessions":[{...,"trust_score":70,"risk_level":"MEDIUM"}], ...}

curl -s "http://localhost:8000/api/v1/trust-score/$SESSION_ID" -H "Authorization: Bearer $TOKEN"
# -> {"trust_score":70,"risk_level":"MEDIUM","factors":[
#      {"factor_name":"baseline","weight_applied":70,"reason":"Zero Trust neutral-positive baseline"},
#      ... ]}

curl -s http://localhost:8000/api/v1/trust-score/config -H "Authorization: Bearer $TOKEN"
# -> the live weight table + risk bands

# 3 bad-password logins then a new session -> the failed_login_burst factor (-15) appears
```

`/admin/trust-score` shows the score meter, the exact per-factor breakdown,
the user's score history, and the live weight table. `/admin/alerts` is the
MFA events feed. Weights/thresholds/VPN CIDRs/MFA policy are all in
`app/core/config.py` (env-overridable).

```bash
cd backend && pytest          # 72 tests: health/stubs + auth + sessions + ACL + trust + MFA
cd frontend && npm run build  # type-checks and builds to dist/
```

## Environment variables

See `.env.example` (root, read by Docker Compose) and
`backend/.env.example` / `frontend/.env.example` (native/non-Docker runs).
Never commit a real `.env` — `.gitignore` already excludes it. In
particular, change `JWT_SECRET_KEY` and `POSTGRES_PASSWORD` from their
placeholder values before any shared or deployed use.

## Next module

Module 7 — Continuous Trust Evaluation: keep re-scoring the trust score during
an *active* session in response to security events (IP change, VPN, abnormal
download/request rate), re-triggering MFA (reusing Module 6's
`create_challenge`) or forcing the S2→S3 revocation Module 3 already defines
when risk becomes unacceptable. Do not start Module 8+ before Module 7 works,
per the project's development order.
