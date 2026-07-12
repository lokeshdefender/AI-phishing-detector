import importlib

from fastapi.testclient import TestClient


def test_health_endpoint_returns_status_database_and_version(tmp_path, monkeypatch):
    db_path = tmp_path / "health.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("APP_VERSION", "9.9.9-test")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    client = TestClient(main_module.app)
    response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] in {"ok", "degraded"}
    assert payload["database"] in {"connected", "disconnected"}
    assert payload["version"] == "9.9.9-test"
