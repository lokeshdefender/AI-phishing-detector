import importlib

from fastapi.testclient import TestClient

from tests.conftest import authenticate_client


def test_update_investigation_endpoint_updates_case_fields(tmp_path, monkeypatch):
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
                case_id="CASE-000020",
                title="Invoice lure",
                submitted_text="Please review the invoice",
                sender="billing@example.com",
                urls="[]",
                phishing_score=68,
                confidence=80,
                threat_level="MEDIUM",
                analyst_report='{"summary": "Initial review"}',
                analyst_notes="Pending review",
                status="Open",
                summary="Initial review",
            )
        )
        session.commit()

    client = TestClient(main_module.app)
    authenticate_client(client)
    response = client.patch(
        "/investigations/CASE-000020",
        json={
            "status": "Escalated",
            "analyst_notes": "Escalated to SOC",
            "threat_level": "HIGH",
            "summary": "Invoice phishing for finance team",
            "tags": ["finance", "invoice"],
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "Escalated"
    assert response.json()["analyst_notes"] == "Escalated to SOC"
    assert response.json()["threat_level"] == "HIGH"
    assert response.json()["summary"] == "Invoice phishing for finance team"
    assert response.json()["tags"] == ["finance", "invoice"]
