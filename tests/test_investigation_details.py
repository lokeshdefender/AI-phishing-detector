import importlib

from fastapi.testclient import TestClient

from tests.conftest import authenticate_client


def test_investigation_detail_endpoint_returns_case_data(tmp_path, monkeypatch):
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
                case_id="CASE-000010",
                title="Invoice lure",
                submitted_text="Please review the invoice",
                sender="billing@example.com",
                urls="https://example.com/invoice",
                phishing_score=68,
                confidence=80,
                threat_level="HIGH",
                analyst_report='{"threat_level": "HIGH"}',
                analyst_notes="Analyst note",
                status="In Progress",
            )
        )
        session.commit()

    client = TestClient(main_module.app)
    authenticate_client(client)
    response = client.get("/investigations/CASE-000010")

    assert response.status_code == 200
    assert response.json()["case_id"] == "CASE-000010"
    assert response.json()["title"] == "Invoice lure"


def test_investigation_details_html_includes_copilot_panel(tmp_path, monkeypatch):
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
                case_id="CASE-000011",
                title="Copilot UI case",
                submitted_text="test",
                sender="tester@example.com",
                urls="[]",
                phishing_score=12,
                confidence=30,
                threat_level="LOW",
                analyst_report="{}",
                analyst_notes="",
                status="Open",
            )
        )
        session.commit()

    client = TestClient(main_module.app)
    authenticate_client(client)
    response = client.get(
        "/investigations/CASE-000011",
        headers={"Accept": "text/html"},
    )

    assert response.status_code == 200
    body = response.text
    assert "AI Investigation Copilot" in body
    assert "MITRE ATT&CK Mapping" in body
    assert "id=\"copilotHistory\"" in body
    assert "Summarize Investigation" in body
    assert "Generate Technical Summary" in body
