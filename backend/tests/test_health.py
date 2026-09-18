"""
Module 1 smoke test: confirms the API boots and the /health contract shape
is correct. Does NOT assert database/redis are reachable here, since CI
environments may run this without those services — that live check is what
you exercise manually via `curl localhost:8000/api/v1/health` in dev/Docker.
"""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_ok():
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "running"


def test_health_shape():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.json()
    assert "status" in body
    assert "dependencies" in body
    assert set(body["dependencies"].keys()) == {"database", "redis"}


def test_no_placeholder_endpoints_remain():
    # Modules 1-9 (health, auth, sessions/ws, acl, trust-score, mfa, security,
    # dashboard, simulation) are all implemented now and covered by their own
    # test_*.py files -- there is no longer a still-unbuilt module stub to
    # honestly report 501 here (this test used to check exactly that for
    # Module 9's own /simulate/{event_type}). Module 10 (Testing &
    # Evaluation) has no REST surface of its own to stub. Smoke-check that
    # the once-placeholder route is now real and auth-gated instead of gone.
    response = client.post(
        "/api/v1/simulate/ip_change", json={"session_id": "does-not-matter"}
    )
    assert response.status_code == 401
