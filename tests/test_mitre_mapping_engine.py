import importlib
import json


def _boot(tmp_path, monkeypatch):
    db_path = tmp_path / "mitre_engine.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.mitre_mapping as mitre_module

    database_module = importlib.reload(database_module)
    mitre_module = importlib.reload(mitre_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")
    return database_module, mitre_module


def test_mitre_mapping_engine_generates_evidence_backed_mappings(tmp_path, monkeypatch):
    database_module, mitre_module = _boot(tmp_path, monkeypatch)

    with database_module.SessionLocal() as session:
        inv = database_module.Investigation(
            case_id="CASE-800001",
            title="MITRE mapping case",
            submitted_text="From: attacker@example.com Click https://evil.example/login and verify your password now",
            sender="attacker@example.com",
            urls=json.dumps(["https://evil.example/login"]),
            phishing_score=88,
            confidence=92,
            threat_level="HIGH",
            analyst_report=json.dumps(
                {
                    "key_indicators": [{"indicator": "credential_harvest", "weight": 50}],
                    "heuristic_rules": [{"rule": "brand_impersonation", "field": "domain", "detail": "Domain text references brand."}],
                }
            ),
            analyst_notes="Observed suspicious login lure and potential persistence keyword in analyst notes.",
            evidence=json.dumps(["evil.example", "8.8.8.8"]),
            status="Open",
            graph=json.dumps(
                {
                    "nodes": [{"id": "n1", "type": "URL", "label": "https://evil.example/login", "metadata": {}}],
                    "edges": [{"source": "n1", "target": "n2", "relationship": "resolves_to_domain", "metadata": {}}],
                    "metadata": {"source_signature": "abc"},
                }
            ),
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
                reputation=85,
                confidence=90,
                risk_score=89,
                detection_summary="Malicious URL",
                evidence=json.dumps([]),
                provider_responses=json.dumps({"VirusTotal": {"status": "ok", "data": {"malicious": 12, "suspicious": 2, "harmless": 40}}}),
            )
        )
        session.commit()

        payload = mitre_module.refresh_investigation_mitre(session, inv, force=True)
        session.commit()

    assert isinstance(payload.get("mappings"), list)
    assert payload["metadata"].get("source_signature")
    assert payload["mappings"]

    attack_ids = {item["attack_id"] for item in payload["mappings"]}
    assert "T1566.002" in attack_ids
    assert "T1056.003" in attack_ids

    for item in payload["mappings"]:
        assert item["technique"]
        assert item["tactic"]
        assert isinstance(item["confidence"], int)
        assert isinstance(item["evidence"], list)
        assert item["explanation"]


def test_mitre_mapping_engine_returns_empty_when_evidence_insufficient(tmp_path, monkeypatch):
    database_module, mitre_module = _boot(tmp_path, monkeypatch)

    with database_module.SessionLocal() as session:
        inv = database_module.Investigation(
            case_id="CASE-800002",
            title="Minimal case",
            submitted_text="Hello team",
            sender="team@example.com",
            urls="[]",
            phishing_score=5,
            confidence=10,
            threat_level="LOW",
            analyst_report="{}",
            analyst_notes="Routine message",
            evidence="[]",
            status="Open",
        )
        session.add(inv)
        session.commit()
        session.refresh(inv)

        payload = mitre_module.refresh_investigation_mitre(session, inv, force=True)

    assert payload["mappings"] == []
