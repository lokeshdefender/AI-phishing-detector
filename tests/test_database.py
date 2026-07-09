from sqlalchemy import inspect
from sqlalchemy.orm import sessionmaker

from app.database import init_db
from app.models_db import Investigation


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
