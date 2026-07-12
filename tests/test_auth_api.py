import importlib

from fastapi.testclient import TestClient


def _boot(tmp_path, monkeypatch):
    db_path = tmp_path / "auth.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")
    return database_module, main_module


def test_register_login_me_logout_flow(tmp_path, monkeypatch):
    database_module, main_module = _boot(tmp_path, monkeypatch)
    client = TestClient(main_module.app)

    register = client.post(
        "/register",
        json={
            "email": "auth.user@example.com",
            "password": "Password123!",
            "organization_name": "Auth Org",
            "role": "admin",
            "full_name": "Auth User",
        },
    )
    assert register.status_code == 200
    payload = register.json()
    assert payload["user"]["email"] == "auth.user@example.com"
    assert payload["user"]["organization_name"] == "Auth Org"

    with database_module.SessionLocal() as session:
        user = session.query(database_module.User).filter(database_module.User.email == "auth.user@example.com").first()
        assert user is not None
        assert user.password_hash != "Password123!"

    me_response = client.get("/me")
    assert me_response.status_code == 200
    assert me_response.json()["user"]["email"] == "auth.user@example.com"

    logout = client.post("/logout")
    assert logout.status_code == 200

    me_after_logout = client.get("/me")
    assert me_after_logout.status_code == 401


def test_login_rejects_invalid_password(tmp_path, monkeypatch):
    _, main_module = _boot(tmp_path, monkeypatch)
    client = TestClient(main_module.app)

    client.post(
        "/register",
        json={
            "email": "analyst@example.com",
            "password": "Password123!",
            "organization_name": "Org One",
            "role": "analyst",
            "full_name": "Analyst",
        },
    )

    bad_login = client.post(
        "/login",
        json={
            "email": "analyst@example.com",
            "password": "WrongPassword!",
        },
    )
    assert bad_login.status_code == 401
