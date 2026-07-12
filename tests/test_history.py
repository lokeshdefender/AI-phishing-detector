import importlib
from pathlib import Path
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from tests.conftest import authenticate_client


def test_investigations_endpoint_returns_sorted_history(tmp_path, monkeypatch):
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
                case_id="CASE-000002",
                title="Credential harvest attempt",
                submitted_text="Please verify your password",
                sender="attacker@example.com",
                urls="https://example.com/login",
                phishing_score=86,
                confidence=92,
                threat_level="HIGH",
                analyst_report="High-risk report",
                analyst_notes="",
                status="Open",
            )
        )
        session.add(
            database_module.Investigation(
                case_id="CASE-000001",
                title="Suspicious invoice",
                submitted_text="Review the attached invoice",
                sender="billing@example.com",
                urls="https://example.com/invoice",
                phishing_score=44,
                confidence=60,
                threat_level="MEDIUM",
                analyst_report="Medium-risk report",
                analyst_notes="",
                status="In Progress",
            )
        )
        session.commit()

    client = TestClient(main_module.app)
    authenticate_client(client)
    response = client.get("/investigations")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) >= 2
    assert payload[0]["case_id"] == "CASE-000001"
    assert payload[0]["threat_level"] == "MEDIUM"
    assert payload[0]["sender"] == "billing@example.com"


def test_investigations_endpoint_supports_filters_and_dashboard_summary(tmp_path, monkeypatch):
    db_path = tmp_path / "investigations_filters.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    client = TestClient(main_module.app)
    user = authenticate_client(client)

    with database_module.SessionLocal() as session:
        session.add(
            database_module.Investigation(
                case_id="CASE-000101",
                organization_id=user["organization_id"],
                creator_user_id=user["id"],
                title="Open high risk",
                submitted_text="content",
                sender="a@example.com",
                urls="[]",
                phishing_score=80,
                confidence=90,
                threat_level="HIGH",
                analyst_report="{}",
                analyst_notes="",
                status="Open",
                assigned_user_id=user["id"],
            )
        )
        session.add(
            database_module.Investigation(
                case_id="CASE-000102",
                organization_id=user["organization_id"],
                creator_user_id=user["id"],
                title="Closed case",
                submitted_text="content",
                sender="b@example.com",
                urls="[]",
                phishing_score=22,
                confidence=50,
                threat_level="LOW",
                analyst_report="{}",
                analyst_notes="",
                status="Closed",
            )
        )
        session.commit()

    assigned = client.get("/investigations?filter_by=assigned_to_me")
    assert assigned.status_code == 200
    assert all(item["assigned_user_id"] == user["id"] for item in assigned.json())

    unassigned = client.get("/investigations?filter_by=unassigned")
    assert unassigned.status_code == 200
    assert all(item["assigned_user_id"] is None for item in unassigned.json())

    high = client.get("/investigations?filter_by=high_risk")
    assert high.status_code == 200
    assert all(item["threat_level"] in {"HIGH", "CRITICAL"} for item in high.json())

    dashboard = client.get("/dashboard/summary")
    assert dashboard.status_code == 200
    dashboard_payload = dashboard.json()
    assert "my_open_cases" in dashboard_payload
    assert "assigned_to_me" in dashboard_payload
    assert "recent_team_activity" in dashboard_payload


def test_dashboard_analytics_endpoint_returns_expected_metrics(tmp_path, monkeypatch):
    db_path = tmp_path / "investigations_analytics.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    client = TestClient(main_module.app)
    user = authenticate_client(client)

    now = datetime.now(timezone.utc)

    with database_module.SessionLocal() as session:
        inv_1 = database_module.Investigation(
            case_id="CASE-000201",
            organization_id=user["organization_id"],
            creator_user_id=user["id"],
            title="Critical phishing",
            submitted_text="critical",
            sender="attacker@example.com",
            urls='["https://login.evil.com/reset"]',
            phishing_score=95,
            confidence=90,
            threat_level="CRITICAL",
            analyst_report="{}",
            analyst_notes="",
            status="Open",
            mitre_mappings='{"mappings":[{"attack_id":"T1566","technique":"Phishing"}]}' ,
            created_at=now,
        )
        inv_2 = database_module.Investigation(
            case_id="CASE-000202",
            organization_id=user["organization_id"],
            creator_user_id=user["id"],
            title="Medium invoice",
            submitted_text="medium",
            sender="billing@example.com",
            urls='["https://portal.target.com/invoice"]',
            phishing_score=50,
            confidence=70,
            threat_level="MEDIUM",
            analyst_report="{}",
            analyst_notes="",
            status="Open",
            mitre_mappings='{"mappings":[{"attack_id":"T1204","technique":"User Execution"}]}' ,
            created_at=now - timedelta(days=2),
        )
        inv_3 = database_module.Investigation(
            case_id="CASE-000203",
            organization_id=user["organization_id"],
            creator_user_id=user["id"],
            title="Low closed case",
            submitted_text="low",
            sender="newsletter@example.com",
            urls='["https://news.safe.org/update"]',
            phishing_score=15,
            confidence=40,
            threat_level="LOW",
            analyst_report="{}",
            analyst_notes="",
            status="Closed",
            mitre_mappings='{"mappings":[{"attack_id":"T1566","technique":"Phishing"}]}' ,
            created_at=now - timedelta(days=8),
        )
        session.add_all([inv_1, inv_2, inv_3])
        session.commit()
        session.refresh(inv_1)
        session.refresh(inv_2)

        session.add(
            database_module.ThreatIntelIndicator(
                investigation_id=inv_1.id,
                ioc_value="login.evil.com",
                ioc_type="Domain",
                source_providers="[]",
                reputation=80,
                confidence=90,
                risk_score=88,
                detection_summary="",
                evidence="[]",
                provider_responses="{}",
            )
        )
        session.add(
            database_module.ThreatIntelIndicator(
                investigation_id=inv_2.id,
                ioc_value="10.0.0.1",
                ioc_type="IP",
                source_providers="[]",
                reputation=45,
                confidence=50,
                risk_score=48,
                detection_summary="",
                evidence="[]",
                provider_responses="{}",
            )
        )
        session.commit()

    response = client.get("/dashboard/analytics?days=30")
    assert response.status_code == 200
    payload = response.json()

    assert payload["kpis"]["total_investigations"] == 3
    assert payload["kpis"]["open_cases"] == 2
    assert payload["kpis"]["closed_cases"] == 1
    assert payload["kpis"]["high_risk_cases"] == 1
    assert payload["kpis"]["medium_risk_cases"] == 1
    assert payload["kpis"]["low_risk_cases"] == 1
    assert payload["kpis"]["created_today"] >= 1
    assert payload["kpis"]["created_this_week"] >= 2

    assert isinstance(payload["charts"]["cases_by_threat_level"], list)
    assert len(payload["charts"]["cases_over_time"]) == 30
    assert any(item["label"] == "Domain" for item in payload["charts"]["top_ioc_types"])
    assert any(item["label"] == "Phishing" for item in payload["charts"]["top_mitre_techniques"])
    assert any(item["label"] in {"login.evil.com", "portal.target.com", "news.safe.org"} for item in payload["charts"]["top_targeted_domains"])
