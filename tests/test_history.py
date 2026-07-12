import importlib
from pathlib import Path

from fastapi.testclient import TestClient

from tests.conftest import authenticate_client


def test_investigations_endpoint_returns_sorted_history(tmp_path, monkeypatch):
    db_path = tmp_path / "investigations.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    with database_module.SessionLocal() as session:
        session.add(
            database_module.Investigation(
                case_id="CASE-000002",
                title="Credential harvest attempt",
                submitted_text="Please verify your password",
                sender="attacker@example.com",
                urls="https://example.com/login",
                phishing_score=86,
                confidence=92,
                threat_level="HIGH",
                analyst_report="High-risk report",
                analyst_notes="",
                status="Open",
            )
        )
        session.add(
            database_module.Investigation(
                case_id="CASE-000001",
                title="Suspicious invoice",
                submitted_text="Review the attached invoice",
                sender="billing@example.com",
                urls="https://example.com/invoice",
                phishing_score=44,
                confidence=60,
                threat_level="MEDIUM",
                analyst_report="Medium-risk report",
                analyst_notes="",
                status="In Progress",
            )
        )
        session.commit()

    client = TestClient(main_module.app)
    authenticate_client(client)
    response = client.get("/investigations")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) >= 2
    assert payload[0]["case_id"] == "CASE-000001"
    assert payload[0]["threat_level"] == "MEDIUM"
    assert payload[0]["sender"] == "billing@example.com"
