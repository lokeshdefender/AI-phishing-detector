import importlib
from fastapi.testclient import TestClient


def test_process_investigation_enrichment_persists_virustotal(tmp_path, monkeypatch):
    db_path = tmp_path / "investigations.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy")

    import app.database as database_module
    import app.main as main_module
    import app.threat_intel_providers as providers_module
    import app.threat_intel as threat_intel_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    providers_module = importlib.reload(providers_module)
    threat_intel_module = importlib.reload(threat_intel_module)

    # init DB
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    # create an investigation record with an IOC in submitted_text
    with database_module.SessionLocal() as session:
        inv = database_module.Investigation(
            case_id="CASE-999999",
            title="VT integration test",
            submitted_text="malicious.example.com",
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

    # monkeypatch the VT client to return a sample payload
    sample = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 2, "harmless": 90}, "last_analysis_date": 1620020000, "reputation": 30, "last_analysis_results": {"EngineA": {"category": "malicious", "result": "malicious"}}}}}
    monkeypatch.setattr("app.threat_intel_providers.VirusTotalClient", lambda api_key: type("C", (), {"get_domain_report": lambda self, d: sample, "get_ip_report": lambda self, i: sample, "get_file_report": lambda self, h: sample, "get_url_report": lambda self, u: sample})())

    # run enrichment
    results = threat_intel_module.process_investigation_enrichment(inv_id)
    assert isinstance(results, list)
    assert any(r.get("summary") for r in results)

    # confirm DB has entries
    with database_module.SessionLocal() as session:
        indicators = session.query(database_module.ThreatIntelIndicator).filter(database_module.ThreatIntelIndicator.investigation_id == inv_id).all()
        assert len(indicators) >= 1
        # provider_responses should include VirusTotal data
        found = False
        for ind in indicators:
            pr = ind.provider_responses
            if pr and "VirusTotal" in pr:
                found = True
        assert found