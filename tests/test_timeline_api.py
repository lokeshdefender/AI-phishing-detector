import importlib
from fastapi.testclient import TestClient

from tests.conftest import authenticate_client

import app.database as database_module
import app.main as main_module


def test_timeline_api_endpoints(tmp_path, monkeypatch):
    global database_module, main_module
    db_path = tmp_path / "api_timeline.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)

    database_module.init_db(database_url=f"sqlite:///{db_path}")

    with database_module.SessionLocal() as session:
        inv = database_module.Investigation(
            case_id="CASE-300001",
            title="API Timeline Test",
            submitted_text="test",
            sender="tester@example.com",
            urls="[]",
            phishing_score=0,
            confidence=0,
            threat_level="MINIMAL",
            analyst_report="{}",
            analyst_notes="",
            status="Open",
        )
        session.add(inv)
        session.commit()
        session.refresh(inv)
        inv_id = inv.id
        case_id = inv.case_id

    client = TestClient(main_module.app)
    authenticate_client(client)

    # GET timeline empty
    resp = client.get(f"/investigations/{case_id}/timeline")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # POST manual event
    payload = {"event_type": "manual_note", "title": "Note", "description": "Manual note added", "source": "analyst", "metadata": {"foo": "bar"}}
    resp2 = client.post(f"/investigations/{case_id}/timeline", json=payload)
    assert resp2.status_code == 200
    ev = resp2.json()
    assert ev["event_type"] == "manual_note"

    # GET timeline should now include the event
    resp3 = client.get(f"/investigations/{case_id}/timeline")
    items = resp3.json()
    assert any(i["event_type"] == "manual_note" for i in items)
    assert all("case_id" in i for i in items)


def test_email_ingestion_adds_timeline_activity(tmp_path, monkeypatch):
    db_path = tmp_path / "timeline_eml.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module
    from tests.conftest import authenticate_client

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    client = TestClient(main_module.app)
    authenticate_client(client)

    eml = b"""From: ingest@example.com
To: team@example.com
Subject: Ingestion Event
Message-ID: <ingest-01@example.com>

Body with https://example.com/login
"""

    response = client.post(
        "/analyze-eml",
        files={"file": ("ingest.eml", eml, "message/rfc822")},
    )
    assert response.status_code == 200
    case_id = response.json()["case_id"]

    timeline = client.get(f"/investigations/{case_id}/timeline")
    assert timeline.status_code == 200
    events = timeline.json()
    assert any(ev["event_type"] == "email_ingested" for ev in events)


def test_evidence_upload_and_delete_add_timeline_events(tmp_path, monkeypatch):
    db_path = tmp_path / "timeline_evidence.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("EVIDENCE_STORAGE_PATH", str(tmp_path / "timeline_evidence_store"))

    import app.database as database_module
    import app.evidence_storage as evidence_storage_module
    import app.main as main_module
    from tests.conftest import authenticate_client

    database_module = importlib.reload(database_module)
    evidence_storage_module = importlib.reload(evidence_storage_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    client = TestClient(main_module.app)
    authenticate_client(client)

    create_case = client.post(
        "/investigate",
        json={"input_text": "Timeline evidence test case"},
    )
    assert create_case.status_code == 200
    case_id = create_case.json()["case_id"]

    upload = client.post(
        f"/investigations/{case_id}/evidence",
        files={"file": ("timeline.txt", b"timeline-evidence", "text/plain")},
    )
    assert upload.status_code == 200
    evidence_id = upload.json()["evidence_id"]

    remove = client.delete(f"/investigations/{case_id}/evidence/{evidence_id}")
    assert remove.status_code == 200

    timeline = client.get(f"/investigations/{case_id}/timeline")
    assert timeline.status_code == 200
    events = timeline.json()
    assert any(ev["event_type"] == "evidence_uploaded" for ev in events)
    assert any(ev["event_type"] == "evidence_deleted" for ev in events)
