import importlib

from fastapi.testclient import TestClient
from sqlalchemy import inspect
from sqlalchemy.orm import sessionmaker

from app.database import init_db
from app.models_db import Investigation
from tests.conftest import authenticate_client


def test_database_initializes_investigations_table(tmp_path):
    db_path = tmp_path / "investigations.db"
    engine = init_db(database_url=f"sqlite:///{db_path}")

    assert engine is not None
    assert inspect(engine).has_table("investigations")


def test_investigation_model_can_be_persisted(tmp_path):
    db_path = tmp_path / "investigations.db"
    engine = init_db(database_url=f"sqlite:///{db_path}")
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as session:
        investigation = Investigation(
            case_id="CASE-000001",
            title="Suspicious payment request",
            submitted_text="Please verify your password",
            sender="phisher@example.com",
            subject="Important Update",
            recipients='["soc@example.com"]',
            message_id="<mid-123@example.com>",
            attachment_count=2,
            urls="https://example.com/login",
            phishing_score=78,
            confidence=90,
            threat_level="HIGH",
            analyst_report="High confidence phishing attempt",
            analyst_notes="Initial triage",
            status="Open",
        )
        session.add(investigation)
        session.commit()

        saved = session.query(Investigation).filter_by(case_id="CASE-000001").one()

    assert saved.title == "Suspicious payment request"
    assert saved.status == "Open"
    assert saved.subject == "Important Update"
    assert saved.message_id == "<mid-123@example.com>"
    assert saved.attachment_count == 2


def test_analyze_endpoint_creates_investigation_record(tmp_path, monkeypatch):
    db_path = tmp_path / "investigations.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)

    client = TestClient(main_module.app)
    authenticate_client(client)
    response = client.post(
        "/analyze",
        json={"email_text": "Please verify your account at https://example.com/login"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["case_id"].startswith("CASE-")

    with database_module.SessionLocal() as session:
        saved = session.query(Investigation).filter_by(case_id=payload["case_id"]).first()

    assert saved is not None
    assert saved.status == "Open"
