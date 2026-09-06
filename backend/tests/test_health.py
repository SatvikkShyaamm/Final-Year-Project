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


def test_placeholder_endpoints_return_501():
    # Confirms module-2..9 stubs are wired but honestly report "not implemented"
    # rather than silently succeeding.
    for method, path in [
        ("post", "/api/v1/auth/login"),
        ("get", "/api/v1/sessions"),
        ("get", "/api/v1/acl/rules"),
        ("get", "/api/v1/trust-score/some-user"),
        ("post", "/api/v1/mfa/challenge"),
        ("get", "/api/v1/dashboard/overview"),
        ("post", "/api/v1/simulate/ip_change"),
    ]:
        response = getattr(client, method)(path)
        assert response.status_code == 501
