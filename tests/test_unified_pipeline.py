import importlib
import json

from fastapi.testclient import TestClient


def test_investigate_endpoint_detects_input_and_persists_pipeline_context(tmp_path, monkeypatch):
    db_path = tmp_path / "investigations.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    client = TestClient(main_module.app)
    response = client.post(
        "/investigate",
        json={"input_text": "Urgent password reset required. Click https://evil.example/login and verify your account."},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["investigation_type"] in {"email", "url", "ioc", "soc_alert"}
    assert payload["pipeline_stage"] == "Analyzing"
    assert payload["summary"]
    assert payload["timeline"]
    assert payload["case_id"]


def test_investigation_detail_endpoint_exposes_pipeline_fields(tmp_path, monkeypatch):
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
                case_id="CASE-000040",
                title="Unified pipeline case",
                submitted_text="Phishing alert",
                sender="analyst@example.com",
                urls="[]",
                phishing_score=72,
                confidence=88,
                threat_level="HIGH",
                analyst_report='{"threat_level": "HIGH"}',
                analyst_notes="Reviewed",
                status="Open",
                investigation_type="email",
                pipeline_stage="Analyzing",
                timeline=json.dumps([{"stage": "New", "message": "Investigation created"}]),
                graph=json.dumps([{"source": "Email", "target": "Threat Intelligence"}]),
            )
        )
        session.commit()

    client = TestClient(main_module.app)
    response = client.get("/investigations/CASE-000040")

    assert response.status_code == 200
    payload = response.json()
    assert payload["investigation_type"] == "email"
    assert payload["pipeline_stage"] == "Analyzing"
    assert payload["timeline"]
    assert payload["graph"]
