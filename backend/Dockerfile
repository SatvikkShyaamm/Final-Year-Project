FROM python:3.11-slim

WORKDIR /app

# System deps needed to build psycopg2-binary's transitive deps on some
# base images; kept minimal on purpose.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Apply DB migrations before serving. From Module 2 on there is real schema
# (starting with the users table), so the container brings the DB up to head
# on every start; `alembic upgrade` is a no-op when already current.
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"]
