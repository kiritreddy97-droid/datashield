from fastapi.testclient import TestClient

from app.main import app


def test_health_and_openapi():
    with TestClient(app) as client:
        assert client.get("/health").json() == {"status": "ok"}
        assert "/health" in client.get("/openapi.json").json()["paths"]
