import importlib
import json
from pathlib import Path




def test_timeline_event_persistence(tmp_path, monkeypatch):
    db_path = tmp_path / "test_timeline.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    database_module = importlib.import_module("app.database")
    importlib.reload(database_module)
    # init DB
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    with database_module.SessionLocal() as session:
        # create a minimal investigation via direct model insert
        inv = database_module.Investigation(
            case_id="CASE-200001",
            title="Timeline test",
            submitted_text="test input",
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

        # append an event
        ev = database_module.append_timeline_event(
            inv_id,
            event_type="test_event",
            title="Test Event",
            description="This is a test",
            source="system",
            metadata={"k": "v"},
            session=session,
        )
        assert ev["event_type"] == "test_event"

        events = database_module.get_timeline_events(inv_id, order="asc")
        assert len(events) >= 1
        # last event should match
        found = [e for e in events if e["event_type"] == "test_event"]
        assert found
        assert found[0]["metadata"]["k"] == "v"
