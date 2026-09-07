# ZTSAACM Security Dashboard

A Zero Trust Session-Aware Access Control system (based on Chang & Xu's
ZTSAACM base paper) extended with Trust Score, Adaptive MFA, and
Continuous Trust Evaluation, presented through a SOC-style admin
dashboard. See `docs/architecture.md` and the project's Claude project
docs for full context before making architectural changes.

**Module status:** Modules 1 (Project Foundation), 2 (Authentication) and
3 (Session Lifecycle) are implemented. Modules 4-9 are still scaffolding —
their endpoints exist as routes but honestly return `501 Not Implemented`;
nothing is mocked to look like it works. See `Project status.md`.

## What actually works right now

- Backend (FastAPI) boots and serves `GET /api/v1/health`, which performs
  a **live** `SELECT 1` against Postgres and a **live** `PING` against
  Redis — it reports "unreachable" if either is actually down, it doesn't
  fake success.
- **Authentication (Module 2)** — real:
  - `POST /api/v1/auth/register` hashes the password with bcrypt, stores a
    `users` row, returns a signed JWT. The **first** account on a fresh DB
    becomes `admin`; the rest are `user`.
  - `POST /api/v1/auth/login` verifies credentials and returns a JWT.
  - `GET /api/v1/auth/me` validates the `Authorization: Bearer` token and
    returns the current user; bad/expired/forged tokens get `401`.
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
- Frontend: a real login/register screen, a JWT-aware axios client
  (attaches the token, redirects to `/login` on `401`), an `AuthProvider`
  that rehydrates the session on refresh, route guards (`/admin` admin-only,
  `/portal` any logged-in user), a `SessionProvider` that opens the
  signalling WebSocket after login and reconnects on unexpected drops, a
  **live Live Sessions** table (auto-refreshing, with per-row Terminate),
  and a session card + WebSocket status indicator in the portal/header.
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
│   └── l-pep/                  # reserved for Module 4's ACL enforcement component
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app + CORS + router mount
│   │   ├── core/                # config, DB session, Redis client, logging
│   │   ├── api/deps.py          # get_db + get_current_user/get_current_admin (Module 2)
│   │   ├── api/v1/endpoints/    # one file per module's REST endpoints
│   │   ├── core/security.py     # bcrypt hashing + JWT encode/decode (Module 2)
│   │   ├── models/              # SQLAlchemy models — user.py (M2), session.py (M3)
│   │   ├── schemas/             # Pydantic schemas — auth.py (M2), session.py (M3)
│   │   ├── services/            # business logic per module — auth/ (M2), session/ (M3)
│   │   └── ws/                  # connection_manager.py + handshake auth.py (Module 3)
│   ├── alembic/versions/        # DB migrations — 0001 users, 0002 sessions
│   ├── tests/                   # test_health / test_auth / test_sessions
│   └── requirements.txt
└── frontend/
    └── src/
        ├── pages/admin/         # one page per dashboard section (Module 8)
        ├── auth/                # AuthProvider, ProtectedRoute, token store (M2)
        ├── session/            # SessionProvider, useSession (Module 3)
        ├── components/layout/   # Sidebar, AdminLayout
        ├── components/common/   # RiskBadge, PlaceholderCard
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

**Authentication (Module 2)** end to end:

```bash
# register (first account on a fresh DB is the admin)
curl -s -X POST http://localhost:8000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","email":"admin@example.com","password":"change-me-123"}'

# log in, capture the token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"change-me-123"}' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# use it
curl -s http://localhost:8000/api/v1/auth/me -H "Authorization: Bearer $TOKEN"
```

In the browser: http://localhost:5173/login → register/sign in → the admin
lands on the SOC dashboard, a normal user on `/portal`; a missing/expired
token bounces back to `/login`.

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

```bash
cd backend && pytest          # 31 tests: health/stubs + auth + session lifecycle
cd frontend && npm run build  # type-checks and builds to dist/
```

## Environment variables

See `.env.example` (root, read by Docker Compose) and
`backend/.env.example` / `frontend/.env.example` (native/non-Docker runs).
Never commit a real `.env` — `.gitignore` already excludes it. In
particular, change `JWT_SECRET_KEY` and `POSTGRES_PASSWORD` from their
placeholder values before any shared or deployed use.

## Next module

Module 4 — Dynamic ACL Management (create an ACL rule when a session opens,
remove it when the session ends, bound to the FSM S2 state; iptables/ipset on
Linux). It hooks into the `session.opened` / `session.closed` events and the
`terminate_session` path this module already emits. Completing it makes the
core base-paper implementation work end to end. Do not start Module 5+ before
Module 4 works, per the project's development order.
