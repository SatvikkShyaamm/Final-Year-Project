#!/usr/bin/env bash
# One-time local dev bootstrap (native, non-Docker path).
# Run from the repo root: ./scripts/dev-setup.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Backend: creating virtualenv and installing dependencies"
cd "$ROOT_DIR/backend"
python3 -m venv .venv
./.venv/bin/pip install --upgrade pip
./.venv/bin/pip install -r requirements.txt
[ -f .env ] || cp .env.example .env

echo "==> Frontend: installing dependencies"
cd "$ROOT_DIR/frontend"
npm install
[ -f .env ] || cp .env.example .env

echo "==> Root .env"
cd "$ROOT_DIR"
[ -f .env ] || cp .env.example .env

cat <<'EOF'

Done. Next steps:
  1. Make sure Postgres and Redis are running and match backend/.env
     (or just run: docker compose up postgres redis)
  2. Backend:  cd backend  && source .venv/bin/activate && uvicorn app.main:app --reload --port 8000
  3. Frontend: cd frontend && npm run dev
  4. Check:    curl http://localhost:8000/api/v1/health
EOF
