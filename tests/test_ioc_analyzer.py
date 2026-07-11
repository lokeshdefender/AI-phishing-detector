import importlib

from fastapi.testclient import TestClient


def test_ioc_analysis_endpoint_detects_type_and_persists_case(tmp_path, monkeypatch):
    db_path = tmp_path / "investigations.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")

    client = TestClient(main_module.app)
    response = client.post(
        "/ioc-analyze",
        json={"ioc_value": "8.8.8.8"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["ioc_type"] == "IP Address"
    assert payload["normalized"]["value"] == "8.8.8.8"
    assert payload["reputation_score"] >= 0
    assert payload["summary"]
    assert payload["case_id"]


def test_email_heuristics_score_local_part_and_disposable_domain():
    from app.ioc_analyzer import normalize_ioc_analysis

    result = normalize_ioc_analysis("admin.verify-paypal123@tempmail.com")

    assert result["ioc_type"] == "Email Address"
    assert result["heuristic_score"] > 0
    assert result["reputation_score"] >= result["base_reputation_score"]
    assert any(finding["rule"] == "suspicious_term" and finding["field"] == "email_local_part" for finding in result["heuristic_findings"])
    assert any(finding["rule"] == "disposable_provider" for finding in result["heuristic_findings"])
    assert "Heuristic signals" in result["summary"]


def test_domain_and_url_heuristics_flag_typosquatting_and_structure():
    from app.ioc_analyzer import normalize_ioc_analysis

    result = normalize_ioc_analysis("https://micros0ft-login-secure-example.com/verify-account?reset=1")

    assert result["ioc_type"] == "URL"
    assert result["heuristic_score"] > 0
    assert result["reputation_score"] >= result["base_reputation_score"]
    assert any(finding["rule"] in {"typosquatting", "brand_impersonation"} for finding in result["heuristic_findings"])
    assert any(finding["rule"] == "suspicious_term" and finding["field"] in {"url_host", "url_path", "url_query"} for finding in result["heuristic_findings"])


def test_filename_heuristics_flag_suspicious_attachment_names():
    from app.ioc_analyzer import normalize_ioc_analysis

    result = normalize_ioc_analysis("invoice-payment-update-2026.docm")

    assert result["ioc_type"] == "File Name"
    assert result["heuristic_score"] > 0
    assert result["reputation_score"] >= result["base_reputation_score"]
    assert any(finding["field"] == "file_name" for finding in result["heuristic_findings"])
    assert any(finding["rule"] in {"suspicious_term", "dangerous_extension", "excessive_hyphens"} for finding in result["heuristic_findings"])
