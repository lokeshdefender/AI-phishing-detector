import importlib

from fastapi.testclient import TestClient


def _boot(tmp_path, monkeypatch):
    db_path = tmp_path / "collaboration_assignment.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")
    return database_module, main_module


def _register(client, email, role, org):
    response = client.post(
        "/register",
        json={
            "email": email,
            "password": "Password123!",
            "organization_name": org,
            "role": role,
            "full_name": email.split("@")[0],
        },
    )
    assert response.status_code == 200
    return response.json()["user"]


def test_assignment_updates_fields_and_logs_activity(tmp_path, monkeypatch):
    _, main_module = _boot(tmp_path, monkeypatch)

    admin_client = TestClient(main_module.app)
    admin_user = _register(admin_client, "admin-collab@example.com", "admin", "Team Org")

    analyst_client = TestClient(main_module.app)
    analyst_user = _register(analyst_client, "analyst-collab@example.com", "analyst", "Team Org")

    created = admin_client.post(
        "/investigate",
        json={"input_text": "Review suspicious login link https://collab-assignment.test/login"},
    )
    assert created.status_code == 200
    case_id = created.json()["case_id"]

    assign = admin_client.patch(
        f"/investigations/{case_id}/assignment",
        json={"assigned_user_id": analyst_user["id"]},
    )
    assert assign.status_code == 200
    payload = assign.json()
    assert payload["assigned_user_id"] == analyst_user["id"]
    assert payload["assigned_by"] == admin_user["id"]
    assert payload["assigned_to"]
    assert payload["assigned_at"] is not None

    detail = admin_client.get(f"/investigations/{case_id}")
    assert detail.status_code == 200
    assert detail.json()["assigned_user_id"] == analyst_user["id"]

    activity = admin_client.get(f"/investigations/{case_id}/activity")
    assert activity.status_code == 200
    assert any(item["event_type"] == "assignment_changed" for item in activity.json()["activity"])
