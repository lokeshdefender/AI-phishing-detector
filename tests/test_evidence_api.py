import hashlib
import importlib

from fastapi.testclient import TestClient

from tests.conftest import authenticate_client


def _boot(tmp_path, monkeypatch, *, max_size_bytes: int | None = None):
    db_path = tmp_path / "evidence_api.db"
    evidence_path = tmp_path / "evidence_store"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("EVIDENCE_STORAGE_PATH", str(evidence_path))
    if max_size_bytes is not None:
        monkeypatch.setenv("EVIDENCE_MAX_FILE_SIZE_BYTES", str(max_size_bytes))

    import app.database as database_module
    import app.evidence_storage as evidence_storage_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    evidence_storage_module = importlib.reload(evidence_storage_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")
    return database_module, evidence_storage_module, main_module


def _create_case(client: TestClient) -> str:
    response = client.post(
        "/investigate",
        json={"input_text": "Suspicious invoice at https://evil.example/invoice"},
    )
    assert response.status_code == 200
    return response.json()["case_id"]


def test_evidence_upload_list_download_delete_flow(tmp_path, monkeypatch):
    _, _, main_module = _boot(tmp_path, monkeypatch)

    client = TestClient(main_module.app)
    authenticate_client(client, role="admin")
    case_id = _create_case(client)

    content = b"SOC evidence file"
    expected_sha = hashlib.sha256(content).hexdigest()

    upload = client.post(
        f"/investigations/{case_id}/evidence",
        files={"file": ("notes.txt", content, "text/plain")},
    )
    assert upload.status_code == 200
    uploaded = upload.json()
    assert uploaded["case_id"] == case_id
    assert uploaded["original_filename"] == "notes.txt"
    assert uploaded["sha256"] == expected_sha

    listed = client.get(f"/investigations/{case_id}/evidence")
    assert listed.status_code == 200
    items = listed.json()["items"]
    assert len(items) == 1
    evidence_id = items[0]["evidence_id"]

    downloaded = client.get(f"/investigations/{case_id}/evidence/{evidence_id}/download")
    assert downloaded.status_code == 200
    assert downloaded.content == content

    deleted = client.delete(f"/investigations/{case_id}/evidence/{evidence_id}")
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True

    listed_after = client.get(f"/investigations/{case_id}/evidence")
    assert listed_after.status_code == 200
    assert listed_after.json()["items"] == []


def test_evidence_upload_rejects_invalid_type(tmp_path, monkeypatch):
    _, _, main_module = _boot(tmp_path, monkeypatch)

    client = TestClient(main_module.app)
    authenticate_client(client, role="admin")
    case_id = _create_case(client)

    upload = client.post(
        f"/investigations/{case_id}/evidence",
        files={"file": ("payload.exe", b"MZ", "application/octet-stream")},
    )
    assert upload.status_code == 422


def test_evidence_upload_rejects_oversized_file(tmp_path, monkeypatch):
    _, _, main_module = _boot(tmp_path, monkeypatch, max_size_bytes=20)

    client = TestClient(main_module.app)
    authenticate_client(client, role="admin")
    case_id = _create_case(client)

    upload = client.post(
        f"/investigations/{case_id}/evidence",
        files={"file": ("notes.txt", b"A" * 21, "text/plain")},
    )
    assert upload.status_code == 413


def test_viewer_cannot_upload_or_delete_evidence(tmp_path, monkeypatch):
    _, _, main_module = _boot(tmp_path, monkeypatch)

    admin_client = TestClient(main_module.app)
    authenticate_client(admin_client, email="admin-evidence@example.com", organization_name="Evidence Org", role="admin")
    case_id = _create_case(admin_client)

    upload = admin_client.post(
        f"/investigations/{case_id}/evidence",
        files={"file": ("notes.txt", b"for download", "text/plain")},
    )
    assert upload.status_code == 200
    evidence_id = upload.json()["evidence_id"]

    viewer_client = TestClient(main_module.app)
    authenticate_client(viewer_client, email="viewer-evidence@example.com", organization_name="Evidence Org", role="viewer")

    blocked_upload = viewer_client.post(
        f"/investigations/{case_id}/evidence",
        files={"file": ("viewer.txt", b"x", "text/plain")},
    )
    assert blocked_upload.status_code == 403

    listed = viewer_client.get(f"/investigations/{case_id}/evidence")
    assert listed.status_code == 200
    assert len(listed.json()["items"]) == 1

    downloaded = viewer_client.get(f"/investigations/{case_id}/evidence/{evidence_id}/download")
    assert downloaded.status_code == 200
    assert downloaded.content == b"for download"

    blocked_delete = viewer_client.delete(f"/investigations/{case_id}/evidence/{evidence_id}")
    assert blocked_delete.status_code == 403


def test_cross_org_evidence_access_denied(tmp_path, monkeypatch):
    _, _, main_module = _boot(tmp_path, monkeypatch)

    org_a = TestClient(main_module.app)
    authenticate_client(org_a, email="orga-evidence@example.com", organization_name="OrgA", role="admin")
    case_id = _create_case(org_a)

    upload = org_a.post(
        f"/investigations/{case_id}/evidence",
        files={"file": ("notes.txt", b"orga", "text/plain")},
    )
    assert upload.status_code == 200
    evidence_id = upload.json()["evidence_id"]

    org_b = TestClient(main_module.app)
    authenticate_client(org_b, email="orgb-evidence@example.com", organization_name="OrgB", role="admin")

    denied_list = org_b.get(f"/investigations/{case_id}/evidence")
    assert denied_list.status_code == 404

    denied_download = org_b.get(f"/investigations/{case_id}/evidence/{evidence_id}/download")
    assert denied_download.status_code == 404

    denied_delete = org_b.delete(f"/investigations/{case_id}/evidence/{evidence_id}")
    assert denied_delete.status_code == 404
