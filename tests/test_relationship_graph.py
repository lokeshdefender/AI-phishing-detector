import importlib
import json

from fastapi.testclient import TestClient

from tests.conftest import authenticate_client


def _boot_test_app(tmp_path, monkeypatch):
    db_path = tmp_path / "graph.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")
    return database_module, main_module


def test_graph_endpoint_returns_nodes_and_edges(tmp_path, monkeypatch):
    database_module, main_module = _boot_test_app(tmp_path, monkeypatch)

    with database_module.SessionLocal() as session:
        investigation = database_module.Investigation(
            case_id="CASE-900001",
            title="Graph test",
            submitted_text=(
                "From: sender@example.com\n"
                "To: analyst@example.org\n"
                "Please review https://evil.example/login from 8.8.8.8"
            ),
            sender="sender@example.com",
            urls=json.dumps(["https://evil.example/login"]),
            phishing_score=70,
            confidence=85,
            threat_level="HIGH",
            analyst_report='{"executive_summary": "Suspicious message"}',
            analyst_notes="Investigate login lure",
            evidence=json.dumps(["evil.example", "8.8.8.8"]),
            status="Open",
        )
        session.add(investigation)
        session.commit()
        session.refresh(investigation)

        indicator = database_module.ThreatIntelIndicator(
            investigation_id=investigation.id,
            ioc_value="https://evil.example/login",
            ioc_type="URL",
            source_providers=json.dumps(["VirusTotal", "DNS"]),
            reputation=82,
            confidence=88,
            risk_score=84,
            detection_summary="High risk URL",
            evidence=json.dumps([]),
            provider_responses=json.dumps(
                {
                    "VirusTotal": {
                        "status": "ok",
                        "data": {"malicious": 10, "suspicious": 1, "harmless": 50},
                    },
                    "DNS": {
                        "status": "ok",
                        "records": {"A": ["1.2.3.4"], "MX": [], "NS": []},
                    },
                }
            ),
        )
        session.add(indicator)
        session.commit()

    client = TestClient(main_module.app)
    authenticate_client(client)
    response = client.get("/investigations/CASE-900001/graph")

    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload.get("nodes"), list)
    assert isinstance(payload.get("edges"), list)
    assert payload["metadata"].get("source_signature")

    node_types = {node["type"] for node in payload["nodes"]}
    assert "Investigation" in node_types
    assert "URL" in node_types
    assert "Domain" in node_types
    assert "Threat Intelligence Provider" in node_types
    assert "VirusTotal Result" in node_types

    relationships = {edge["relationship"] for edge in payload["edges"]}
    assert "contains_indicator" in relationships
    assert "resolves_to_domain" in relationships
    assert "enriched_by_provider" in relationships
    assert "enriched_by_virustotal" in relationships


def test_graph_endpoint_refreshes_after_case_update(tmp_path, monkeypatch):
    database_module, main_module = _boot_test_app(tmp_path, monkeypatch)

    with database_module.SessionLocal() as session:
        investigation = database_module.Investigation(
            case_id="CASE-900002",
            title="Graph update test",
            submitted_text="Investigate 8.8.8.8",
            sender="ops@example.com",
            urls="[]",
            phishing_score=25,
            confidence=40,
            threat_level="LOW",
            analyst_report="{}",
            analyst_notes="",
            evidence=json.dumps(["8.8.8.8"]),
            status="Open",
        )
        session.add(investigation)
        session.commit()

    client = TestClient(main_module.app)
    authenticate_client(client)
    before = client.get("/investigations/CASE-900002/graph").json()
    before_signature = before["metadata"].get("source_signature")

    update_response = client.patch(
        "/investigations/CASE-900002",
        json={
            "evidence": ["8.8.8.8", "new-phish.example"],
            "submitted_text": "Investigate 8.8.8.8 and https://new-phish.example/verify",
            "urls": ["https://new-phish.example/verify"],
        },
    )
    assert update_response.status_code == 200

    after = client.get("/investigations/CASE-900002/graph").json()
    after_signature = after["metadata"].get("source_signature")

    assert before_signature
    assert after_signature
    assert before_signature != after_signature
    labels = {node["label"] for node in after["nodes"]}
    assert "https://new-phish.example/verify" in labels


def test_investigation_details_html_includes_relationship_graph_section(tmp_path, monkeypatch):
    database_module, main_module = _boot_test_app(tmp_path, monkeypatch)

    with database_module.SessionLocal() as session:
        session.add(
            database_module.Investigation(
                case_id="CASE-900003",
                title="UI graph test",
                submitted_text="test",
                sender="ui@example.com",
                urls="[]",
                phishing_score=0,
                confidence=0,
                threat_level="MINIMAL",
                analyst_report="{}",
                analyst_notes="",
                status="Open",
            )
        )
        session.commit()

    client = TestClient(main_module.app)
    authenticate_client(client)
    response = client.get(
        "/investigations/CASE-900003",
        headers={"Accept": "text/html"},
    )

    assert response.status_code == 200
    body = response.text
    assert "Relationship Graph" in body
    assert "id=\"relationshipGraph\"" in body
