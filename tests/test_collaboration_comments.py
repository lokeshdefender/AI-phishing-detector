import importlib

from fastapi.testclient import TestClient


def _boot(tmp_path, monkeypatch):
    db_path = tmp_path / "collaboration_comments.db"
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


def test_comment_addition_and_listing(tmp_path, monkeypatch):
    _, main_module = _boot(tmp_path, monkeypatch)

    client = TestClient(main_module.app)
    _register(client, "commenter@example.com", "analyst", "Comment Org")

    created = client.post(
        "/investigate",
        json={"input_text": "Review suspicious attachment and comment workflow"},
    )
    assert created.status_code == 200
    case_id = created.json()["case_id"]

    posted = client.post(
        f"/investigations/{case_id}/comments",
        json={"message": "Initial triage complete. Escalating to SOC lead."},
    )
    assert posted.status_code == 200
    comment_payload = posted.json()
    assert comment_payload["comment_id"]
    assert comment_payload["message"].startswith("Initial triage")

    comments = client.get(f"/investigations/{case_id}/comments")
    assert comments.status_code == 200
    items = comments.json()["comments"]
    assert len(items) >= 1
    assert any("Escalating" in item["message"] for item in items)

    activity = client.get(f"/investigations/{case_id}/activity")
    assert activity.status_code == 200
    assert any(item["event_type"] == "comment_added" for item in activity.json()["activity"])
