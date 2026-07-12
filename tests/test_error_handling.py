import importlib

from fastapi.testclient import TestClient

from tests.conftest import authenticate_client


def test_validation_errors_use_standardized_shape(tmp_path, monkeypatch):
    db_path = tmp_path / "errors_validation.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    client = TestClient(main_module.app)
    authenticate_client(client)

    response = client.post("/analyze", json={"email_text": ""})
    assert response.status_code == 422
    payload = response.json()
    assert "error" in payload
    assert payload["error"]["code"] == 422
    assert payload["error"]["message"] == "Validation error"


def test_http_exceptions_use_standardized_shape(tmp_path, monkeypatch):
    db_path = tmp_path / "errors_http.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    client = TestClient(main_module.app)
    authenticate_client(client)

    response = client.get("/investigations/CASE-DOES-NOT-EXIST")
    assert response.status_code == 404
    payload = response.json()
    assert "error" in payload
    assert payload["error"]["code"] == 404
    assert isinstance(payload["error"]["message"], str)
