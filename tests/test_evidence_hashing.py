import hashlib
import importlib

from fastapi.testclient import TestClient

from tests.conftest import authenticate_client


def _boot(tmp_path, monkeypatch):
    db_path = tmp_path / "evidence_hashing.db"
    evidence_path = tmp_path / "evidence_hashing_store"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("EVIDENCE_STORAGE_PATH", str(evidence_path))

    import app.database as database_module
    import app.evidence_storage as evidence_storage_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    evidence_storage_module = importlib.reload(evidence_storage_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")
    return main_module


def _create_case(client: TestClient) -> str:
    response = client.post(
        "/investigate",
        json={"input_text": "Hashing test case with URL https://example.test/hash"},
    )
    assert response.status_code == 200
    return response.json()["case_id"]


def test_evidence_hash_matches_sha256_of_uploaded_content(tmp_path, monkeypatch):
    main_module = _boot(tmp_path, monkeypatch)

    client = TestClient(main_module.app)
    authenticate_client(client, role="admin")
    case_id = _create_case(client)

    content = b"hash me please"
    expected = hashlib.sha256(content).hexdigest()

    upload = client.post(
        f"/investigations/{case_id}/evidence",
        files={"file": ("hash.txt", content, "text/plain")},
    )
    assert upload.status_code == 200
    assert upload.json()["sha256"] == expected


def test_identical_files_have_identical_hashes(tmp_path, monkeypatch):
    main_module = _boot(tmp_path, monkeypatch)

    client = TestClient(main_module.app)
    authenticate_client(client, role="admin")
    case_id = _create_case(client)

    content = b"same payload"

    upload_one = client.post(
        f"/investigations/{case_id}/evidence",
        files={"file": ("a.txt", content, "text/plain")},
    )
    assert upload_one.status_code == 200

    upload_two = client.post(
        f"/investigations/{case_id}/evidence",
        files={"file": ("b.txt", content, "text/plain")},
    )
    assert upload_two.status_code == 200

    assert upload_one.json()["sha256"] == upload_two.json()["sha256"]
