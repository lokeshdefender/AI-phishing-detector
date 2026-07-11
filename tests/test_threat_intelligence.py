import importlib

from fastapi.testclient import TestClient


def test_extract_iocs_deduplicates_and_normalizes():
    from app.threat_intel import extract_iocs

    text = (
        "Investigate 8.8.8.8 and https://example.com/path and user@example.com "
        "and 5d41402abc4b2a76b9719d911017c592 and example.com"
    )

    results = extract_iocs(text)
    values = {item["ioc_value"] for item in results}

    assert "8.8.8.8" in values
    assert "https://example.com/path" in values
    assert "user@example.com" in values
    assert "5d41402abc4b2a76b9719d911017c592" in values
    assert "example.com" in values
    assert len(results) == len(values)


def test_process_investigation_enrichment_persists_indicators(tmp_path, monkeypatch):
    db_path = tmp_path / "investigations.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module
    import app.threat_intel as threat_intel_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    threat_intel_module = importlib.reload(threat_intel_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    with database_module.SessionLocal() as session:
        investigation = database_module.Investigation(
            case_id="CASE-000030",
            title="Threat intelligence case",
            submitted_text="Investigate 8.8.8.8 and https://example.com/path",
            sender="analyst@example.com",
            urls="[]",
            phishing_score=10,
            confidence=40,
            threat_level="LOW",
            analyst_report='{"summary": "Initial review"}',
            analyst_notes="Pending",
            status="Open",
        )
        session.add(investigation)
        session.commit()
        session.refresh(investigation)

    threat_intel_module.process_investigation_enrichment(investigation.id)

    with database_module.SessionLocal() as session:
        indicators = session.query(threat_intel_module.ThreatIntelIndicator).filter(
            threat_intel_module.ThreatIntelIndicator.investigation_id == investigation.id
        ).all()

    assert len(indicators) >= 2
    assert any(indicator.ioc_type == "IP Address" for indicator in indicators)
    assert any(indicator.ioc_type == "URL" for indicator in indicators)
