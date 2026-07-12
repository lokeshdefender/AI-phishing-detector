import importlib

from fastapi.testclient import TestClient


def _boot(tmp_path, monkeypatch):
    db_path = tmp_path / "multi_tenant.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")
    return database_module, main_module


def _register(client, email, organization):
    response = client.post(
        "/register",
        json={
            "email": email,
            "password": "Password123!",
            "organization_name": organization,
            "role": "analyst",
            "full_name": email.split("@")[0],
        },
    )
    assert response.status_code == 200


def test_cross_org_case_access_is_denied(tmp_path, monkeypatch):
    _, main_module = _boot(tmp_path, monkeypatch)

    org_a_client = TestClient(main_module.app)
    _register(org_a_client, "orga-analyst@example.com", "Org A")

    create_case = org_a_client.post(
        "/investigate",
        json={"input_text": "Review suspicious reset link https://tenant-a-phish.test/login"},
    )
    assert create_case.status_code == 200
    case_id = create_case.json()["case_id"]

    org_b_client = TestClient(main_module.app)
    _register(org_b_client, "orgb-analyst@example.com", "Org B")

    list_cases = org_b_client.get("/investigations")
    assert list_cases.status_code == 200
    assert all(item["case_id"] != case_id for item in list_cases.json())

    detail = org_b_client.get(f"/investigations/{case_id}")
    assert detail.status_code == 404

    graph = org_b_client.get(f"/investigations/{case_id}/graph")
    assert graph.status_code == 404

    comments = org_b_client.get(f"/investigations/{case_id}/comments")
    assert comments.status_code == 404

    add_comment = org_b_client.post(
        f"/investigations/{case_id}/comments",
        json={"message": "Cross-org note"},
    )
    assert add_comment.status_code == 404

    assignment = org_b_client.patch(
        f"/investigations/{case_id}/assignment",
        json={"assigned_user_id": None},
    )
    assert assignment.status_code == 404


def test_cross_org_evidence_access_is_denied(tmp_path, monkeypatch):
    _, main_module = _boot(tmp_path, monkeypatch)

    org_a_client = TestClient(main_module.app)
    _register(org_a_client, "orga-evidence-isolation@example.com", "Org A")

    create_case = org_a_client.post(
        "/investigate",
        json={"input_text": "Org A evidence case"},
    )
    assert create_case.status_code == 200
    case_id = create_case.json()["case_id"]

    upload = org_a_client.post(
        f"/investigations/{case_id}/evidence",
        files={"file": ("orga.txt", b"orga", "text/plain")},
    )
    assert upload.status_code == 200
    evidence_id = upload.json()["evidence_id"]

    org_b_client = TestClient(main_module.app)
    _register(org_b_client, "orgb-evidence-isolation@example.com", "Org B")

    list_response = org_b_client.get(f"/investigations/{case_id}/evidence")
    assert list_response.status_code == 404

    download_response = org_b_client.get(f"/investigations/{case_id}/evidence/{evidence_id}/download")
    assert download_response.status_code == 404

    delete_response = org_b_client.delete(f"/investigations/{case_id}/evidence/{evidence_id}")
    assert delete_response.status_code == 404
