# ZTSAACM Security Dashboard

A Zero Trust Session-Aware Access Control system (based on Chang & Xu's
ZTSAACM base paper) extended with Trust Score, Adaptive MFA, and
Continuous Trust Evaluation, presented through a SOC-style admin
dashboard. See `docs/architecture.md` and the project's Claude project
docs for full context before making architectural changes.

**Module status:** Modules 1 (Project Foundation) and 2 (Authentication)
are implemented. Modules 3-9 are still scaffolding — their endpoints exist
as routes but honestly return `501 Not Implemented`; nothing is mocked to
look like it works. See `Project status.md`.

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
- Frontend: a real login/register screen, a JWT-aware axios client
  (attaches the token, redirects to `/login` on `401`), an `AuthProvider`
  that rehydrates the session on refresh, and route guards — `/admin` is
  admin-only, `/portal` needs any logged-in user.
- Its **System Status** page (`/admin/status`) still calls the real health
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
│   │   ├── models/              # SQLAlchemy models — user.py (Module 2)
│   │   ├── schemas/             # Pydantic request/response schemas — auth.py (Module 2)
│   │   ├── services/            # business logic, one sub-package per module — auth/ (Module 2)
│   │   └── ws/                  # WebSocket session layer (Module 3)
│   ├── alembic/versions/        # DB migrations — 0001 creates the users table
│   ├── tests/
│   └── requirements.txt
└── frontend/
    └── src/
        ├── pages/admin/         # one page per dashboard section (Module 8)
        ├── components/layout/   # Sidebar, AdminLayout
        ├── components/common/   # RiskBadge, PlaceholderCard
        ├── api/                 # axios client + typed API calls
        ├── ws/                  # WebSocket client (Module 3)
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

```bash
cd backend && pytest          # 19 tests: health/stubs + full auth flow (tests/test_auth.py)
cd frontend && npm run build  # type-checks and builds to dist/
```

## Environment variables

See `.env.example` (root, read by Docker Compose) and
`backend/.env.example` / `frontend/.env.example` (native/non-Docker runs).
Never commit a real `.env` — `.gitignore` already excludes it. In
particular, change `JWT_SECRET_KEY` and `POSTGRES_PASSWORD` from their
placeholder values before any shared or deployed use.

## Next module

Module 3 — Session Lifecycle (WebSocket session open/close driving the base
paper's S1→S2→S3 FSM, session state in Redis, logout/timeout/termination).
It builds directly on Module 2's `get_current_user` dependency for the
WebSocket handshake. Do not start Module 4+ before Module 3 works end to end,
per the project's development order.
