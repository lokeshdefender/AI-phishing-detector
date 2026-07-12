import importlib
import json

from fastapi.testclient import TestClient

from tests.conftest import authenticate_client


def _boot(tmp_path, monkeypatch):
    db_path = tmp_path / "mitre_api.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")
    return database_module, main_module


def test_mitre_api_returns_structured_mappings(tmp_path, monkeypatch):
    database_module, main_module = _boot(tmp_path, monkeypatch)

    with database_module.SessionLocal() as session:
        inv = database_module.Investigation(
            case_id="CASE-810001",
            title="MITRE API case",
            submitted_text="Click https://evil.example/login and verify your password",
            sender="phish@example.com",
            urls=json.dumps(["https://evil.example/login"]),
            phishing_score=86,
            confidence=90,
            threat_level="HIGH",
            analyst_report=json.dumps({"key_indicators": [{"indicator": "credential_harvest", "weight": 45}]}),
            analyst_notes="Suspicious credential request",
            evidence=json.dumps(["evil.example"]),
            status="Open",
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
                reputation=84,
                confidence=88,
                risk_score=87,
                detection_summary="Malicious URL",
                evidence=json.dumps([]),
                provider_responses=json.dumps({"VirusTotal": {"status": "ok", "data": {"malicious": 7, "suspicious": 1, "harmless": 44}}}),
            )
        )
        session.commit()

    client = TestClient(main_module.app)
    authenticate_client(client)
    response = client.get("/investigations/CASE-810001/mitre")

    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload.get("mappings"), list)
    assert isinstance(payload.get("metadata"), dict)

    if payload["mappings"]:
        mapping = payload["mappings"][0]
        assert "attack_id" in mapping
        assert "technique" in mapping
        assert "tactic" in mapping
        assert "confidence" in mapping
        assert "evidence" in mapping
        assert "explanation" in mapping


def test_mitre_api_returns_404_for_missing_case(tmp_path, monkeypatch):
    _, main_module = _boot(tmp_path, monkeypatch)
    client = TestClient(main_module.app)
    authenticate_client(client)

    response = client.get("/investigations/CASE-DOES-NOT-EXIST/mitre")
    assert response.status_code == 404
