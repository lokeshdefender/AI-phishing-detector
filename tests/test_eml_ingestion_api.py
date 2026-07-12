import importlib

from fastapi.testclient import TestClient

from tests.conftest import authenticate_client


def test_analyze_eml_uses_unified_pipeline_and_returns_metadata(tmp_path, monkeypatch):
    db_path = tmp_path / "eml_ingestion.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    client = TestClient(main_module.app)
    authenticate_client(client)

    eml = b"""From: phisher@example.com
To: analyst1@example.com, analyst2@example.com
Subject: Verify Account Access
Message-ID: <msg-001@example.com>

Please verify immediately at https://evil.example/login from 8.8.8.8
"""

    response = client.post(
        "/analyze-eml",
        files={"file": ("test.eml", eml, "message/rfc822")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["case_id"].startswith("CASE-")
    assert payload["investigation_type"] == "email"
    assert payload["pipeline_stage"] == "Analyzing"
    assert payload["metadata"]["sender"] == "phisher@example.com"
    assert payload["metadata"]["subject"] == "Verify Account Access"
    assert payload["metadata"]["message_id"] == "<msg-001@example.com>"
    assert len(payload["metadata"]["recipients"]) == 2

    with database_module.SessionLocal() as session:
        record = session.query(database_module.Investigation).filter_by(case_id=payload["case_id"]).first()
        assert record is not None
        assert record.subject == "Verify Account Access"
        assert record.message_id == "<msg-001@example.com>"
        assert int(record.attachment_count or 0) == 0


def test_analyze_eml_rejects_non_eml_extension(tmp_path, monkeypatch):
    db_path = tmp_path / "eml_invalid_extension.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    client = TestClient(main_module.app)
    authenticate_client(client)

    response = client.post(
        "/analyze-eml",
        files={"file": ("not-eml.txt", b"From: a@example.com\n\ntext", "text/plain")},
    )

    assert response.status_code == 422
