# ZTSAACM Security Dashboard

A Zero Trust Session-Aware Access Control system (based on Chang & Xu's
ZTSAACM base paper) extended with Trust Score, Adaptive MFA, and
Continuous Trust Evaluation, presented through a SOC-style admin
dashboard. See `docs/architecture.md` and the project's Claude project
docs for full context before making architectural changes.

**Module status:** Module 1 (Project Foundation) only. Everything below
is scaffolding — real Authentication/Session/ACL/Trust-Score/MFA logic is
added module by module (see `Project status.md`). Endpoints for modules
2-9 exist as routes but honestly return `501 Not Implemented`; nothing is
mocked to look like it works.

## What actually works right now

- Backend (FastAPI) boots and serves `GET /api/v1/health`, which performs
  a **live** `SELECT 1` against Postgres and a **live** `PING` against
  Redis — it reports "unreachable" if either is actually down, it doesn't
  fake success.
- Frontend (React + Vite + Tailwind + React Router) boots, and its
  **System Status** page (`/admin/status`) calls that real health
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
│   │   ├── api/v1/endpoints/    # one file per module's REST endpoints
│   │   ├── models/              # SQLAlchemy models (empty until Module 2+)
│   │   ├── schemas/             # Pydantic request/response schemas
│   │   ├── services/            # business logic, one sub-package per module
│   │   └── ws/                  # WebSocket session layer (Module 3)
│   ├── alembic/                 # DB migrations
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
uvicorn app.main:app --reload --port 8000
```

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

## Verifying the foundation works

```bash
curl http://localhost:8000/api/v1/health
# {"status":"ok","dependencies":{"database":"connected","redis":"connected"}}
```

Then open http://localhost:5173/admin/status in a browser — it should
show the same result rendered live.

```bash
cd backend && pytest        # 3 tests: root, health response shape, module stubs return 501
cd frontend && npm run build  # type-checks and builds to dist/
```

## Environment variables

See `.env.example` (root, read by Docker Compose) and
`backend/.env.example` / `frontend/.env.example` (native/non-Docker runs).
Never commit a real `.env` — `.gitignore` already excludes it. In
particular, change `JWT_SECRET_KEY` and `POSTGRES_PASSWORD` from their
placeholder values before any shared or deployed use.

## Next module

Module 2 — Authentication (registration, login, password hashing, JWT
issuance/validation, auth middleware). Do not start Module 3+ before
Module 2 is working end to end, per the project's development order.
