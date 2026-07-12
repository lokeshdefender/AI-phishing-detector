import importlib
import json


def _boot(tmp_path, monkeypatch):
    db_path = tmp_path / "copilot_context.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module
    import app.copilot as copilot_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    copilot_module = importlib.reload(copilot_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")
    return database_module, copilot_module


def test_copilot_context_assembles_case_scoped_data(tmp_path, monkeypatch):
    database_module, copilot_module = _boot(tmp_path, monkeypatch)

    with database_module.SessionLocal() as session:
        inv = database_module.Investigation(
            case_id="CASE-700001",
            title="Copilot context",
            submitted_text="From: alert@example.com\nTo: user@example.org\nClick https://evil.example/login",
            sender="alert@example.com",
            urls=json.dumps(["https://evil.example/login"]),
            phishing_score=78,
            confidence=90,
            threat_level="HIGH",
            analyst_report=json.dumps({"executive_summary": "High risk phishing attempt."}),
            analyst_notes="Potential credential lure",
            summary="Executive context summary",
            evidence=json.dumps(["evil.example", "8.8.8.8"]),
            status="Open",
            graph=json.dumps({"nodes": [{"id": "n1", "type": "Investigation", "label": "CASE-700001", "metadata": {}}], "edges": []}),
        )
        session.add(inv)
        session.commit()
        session.refresh(inv)

        session.add(
            database_module.ThreatIntelIndicator(
                investigation_id=inv.id,
                ioc_value="https://evil.example/login",
                ioc_type="URL",
                source_providers=json.dumps(["VirusTotal"]),
                reputation=80,
                confidence=85,
                risk_score=88,
                detection_summary="Detected as suspicious",
                evidence=json.dumps([]),
                provider_responses=json.dumps({"VirusTotal": {"status": "ok", "data": {"malicious": 9, "suspicious": 1, "harmless": 45}}}),
            )
        )
        session.commit()

        context = copilot_module.build_investigation_context(session, inv)

    assert context["case_id"] == "CASE-700001"
    assert context["risk_score"] == 78
    assert context["status"] == "Open"
    assert context["executive_summary"]
    assert len(context["threat_intel"]) == 1
    assert len(context["iocs"]) >= 2
    assert isinstance(context["graph"], dict)


def test_copilot_response_is_grounded_when_data_missing(tmp_path, monkeypatch):
    database_module, copilot_module = _boot(tmp_path, monkeypatch)

    with database_module.SessionLocal() as session:
        inv = database_module.Investigation(
            case_id="CASE-700002",
            title="Limited data case",
            submitted_text="minimal",
            sender="",
            urls="[]",
            phishing_score=5,
            confidence=10,
            threat_level="LOW",
            analyst_report="{}",
            analyst_notes="",
            evidence="[]",
            status="Open",
        )
        session.add(inv)
        session.commit()
        session.refresh(inv)

        context = copilot_module.build_investigation_context(session, inv)
        response = copilot_module.generate_copilot_response(context, "Explain VirusTotal findings")

    assert "unavailable" in response.lower() or "does not" in response.lower()
    assert "Evidence" in response


def test_copilot_answers_mitre_questions_from_stored_mappings(tmp_path, monkeypatch):
    database_module, copilot_module = _boot(tmp_path, monkeypatch)

    mitre_payload = {
        "mappings": [
            {
                "attack_id": "T1566.002",
                "technique": "Phishing: Spearphishing Link",
                "tactic": "Initial Access",
                "confidence": 82,
                "evidence": ["URL IOC count: 2", "VirusTotal flagged URL entries: 1"],
                "explanation": "Link-based phishing evidence observed.",
            }
        ],
        "metadata": {"source_signature": "abc"},
    }

    with database_module.SessionLocal() as session:
        inv = database_module.Investigation(
            case_id="CASE-700003",
            title="MITRE copilot case",
            submitted_text="Click https://evil.example/login",
            sender="ops@example.com",
            urls='["https://evil.example/login"]',
            phishing_score=80,
            confidence=85,
            threat_level="HIGH",
            analyst_report="{}",
            analyst_notes="",
            evidence='["evil.example"]',
            mitre_mappings=json.dumps(mitre_payload),
            status="Open",
        )
        session.add(inv)
        session.commit()
        session.refresh(inv)

        context = copilot_module.build_investigation_context(session, inv)
        response = copilot_module.generate_copilot_response(context, "Which ATT&CK techniques apply and why was this technique selected?")

    assert "T1566.002" in response
    assert "Why selected" in response
    assert "Evidence" in response
