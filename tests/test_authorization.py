import importlib

from fastapi.testclient import TestClient


def _boot(tmp_path, monkeypatch):
    db_path = tmp_path / "authorization.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")
    return database_module, main_module


def _register(client, email, role):
    response = client.post(
        "/register",
        json={
            "email": email,
            "password": "Password123!",
            "organization_name": "Role Org",
            "role": role,
            "full_name": email.split("@")[0],
        },
    )
    assert response.status_code == 200


def test_viewer_cannot_run_investigation_or_patch_case(tmp_path, monkeypatch):
    database_module, main_module = _boot(tmp_path, monkeypatch)

    admin_client = TestClient(main_module.app)
    _register(admin_client, "admin@example.com", "admin")

    create_case = admin_client.post(
        "/investigate",
        json={"input_text": "Urgent verify account at https://evil.example/login"},
    )
    assert create_case.status_code == 200
    case_id = create_case.json()["case_id"]

    viewer_client = TestClient(main_module.app)
    _register(viewer_client, "viewer@example.com", "viewer")

    blocked_create = viewer_client.post(
        "/investigate",
        json={"input_text": "This should be blocked"},
    )
    assert blocked_create.status_code == 403

    blocked_patch = viewer_client.patch(
        f"/investigations/{case_id}",
        json={"status": "Closed"},
    )
    assert blocked_patch.status_code == 403

    blocked_assignment = viewer_client.patch(
        f"/investigations/{case_id}/assignment",
        json={"assigned_user_id": None},
    )
    assert blocked_assignment.status_code == 403


def test_analyst_can_update_case(tmp_path, monkeypatch):
    database_module, main_module = _boot(tmp_path, monkeypatch)

    analyst_client = TestClient(main_module.app)
    _register(analyst_client, "analyst@example.com", "analyst")

    create_case = analyst_client.post(
        "/investigate",
        json={"input_text": "Please reset credentials at https://example-phish.test/login"},
    )
    assert create_case.status_code == 200
    case_id = create_case.json()["case_id"]

    update_case = analyst_client.patch(
        f"/investigations/{case_id}",
        json={"status": "Escalated", "analyst_notes": "Escalated for response"},
    )
    assert update_case.status_code == 200
    payload = update_case.json()
    assert payload["status"] == "Escalated"
    assert payload["analyst_notes"] == "Escalated for response"


def test_viewer_can_add_comment_but_cannot_assign(tmp_path, monkeypatch):
    _, main_module = _boot(tmp_path, monkeypatch)

    admin_client = TestClient(main_module.app)
    _register(admin_client, "admin2@example.com", "admin")

    created = admin_client.post(
        "/investigate",
        json={"input_text": "Collaborative case for role checks"},
    )
    assert created.status_code == 200
    case_id = created.json()["case_id"]

    viewer_client = TestClient(main_module.app)
    _register(viewer_client, "viewer2@example.com", "viewer")

    add_comment = viewer_client.post(
        f"/investigations/{case_id}/comments",
        json={"message": "Viewer note for awareness."},
    )
    assert add_comment.status_code == 200

    blocked_assignment = viewer_client.patch(
        f"/investigations/{case_id}/assignment",
        json={"assigned_user_id": None},
    )
    assert blocked_assignment.status_code == 403


def test_viewer_cannot_upload_or_delete_evidence(tmp_path, monkeypatch):
    _, main_module = _boot(tmp_path, monkeypatch)

    admin_client = TestClient(main_module.app)
    _register(admin_client, "admin-evidence-auth@example.com", "admin")

    create_case = admin_client.post(
        "/investigate",
        json={"input_text": "Evidence auth case"},
    )
    assert create_case.status_code == 200
    case_id = create_case.json()["case_id"]

    upload = admin_client.post(
        f"/investigations/{case_id}/evidence",
        files={"file": ("auth.txt", b"evidence", "text/plain")},
    )
    assert upload.status_code == 200
    evidence_id = upload.json()["evidence_id"]

    viewer_client = TestClient(main_module.app)
    _register(viewer_client, "viewer-evidence-auth@example.com", "viewer")

    blocked_upload = viewer_client.post(
        f"/investigations/{case_id}/evidence",
        files={"file": ("blocked.txt", b"x", "text/plain")},
    )
    assert blocked_upload.status_code == 403

    allowed_list = viewer_client.get(f"/investigations/{case_id}/evidence")
    assert allowed_list.status_code == 200

    allowed_download = viewer_client.get(f"/investigations/{case_id}/evidence/{evidence_id}/download")
    assert allowed_download.status_code == 200

    blocked_delete = viewer_client.delete(f"/investigations/{case_id}/evidence/{evidence_id}")
    assert blocked_delete.status_code == 403
