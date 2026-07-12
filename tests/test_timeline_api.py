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
