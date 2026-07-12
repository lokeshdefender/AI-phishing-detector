import importlib
import json

from fastapi.testclient import TestClient

from tests.conftest import authenticate_client


def _boot(tmp_path, monkeypatch):
    db_path = tmp_path / "copilot_api.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    import app.database as database_module
    import app.main as main_module

    database_module = importlib.reload(database_module)
    main_module = importlib.reload(main_module)
    database_module.init_db(database_url=f"sqlite:///{db_path}")
    return database_module, main_module


def _create_case(database_module):
    with database_module.SessionLocal() as session:
        inv = database_module.Investigation(
            case_id="CASE-710001",
            title="Chat API case",
            submitted_text="From: attacker@example.com\nClick https://mal.example/login",
            sender="attacker@example.com",
            urls=json.dumps(["https://mal.example/login"]),
            phishing_score=86,
            confidence=92,
            threat_level="HIGH",
            analyst_report=json.dumps({"executive_summary": "Likely phishing."}),
            analyst_notes="Investigating",
            summary="Likely phishing campaign",
            evidence=json.dumps(["mal.example", "8.8.8.8"]),
            status="Open",
        )
        session.add(inv)
        session.commit()


def test_chat_endpoints_persist_and_retrieve_history(tmp_path, monkeypatch):
    database_module, main_module = _boot(tmp_path, monkeypatch)
    _create_case(database_module)

    client = TestClient(main_module.app)
    authenticate_client(client)

    post_response = client.post(
        "/investigations/CASE-710001/chat",
        json={"message": "Why is this investigation high risk?"},
    )
    assert post_response.status_code == 200
    payload = post_response.json()
    assert payload["case_id"] == "CASE-710001"
    assert len(payload["messages"]) == 2
    assert payload["messages"][0]["role"] == "user"
    assert payload["messages"][1]["role"] == "assistant"
    assert payload["messages"][0]["message_id"]
    assert payload["messages"][1]["message_id"]

    history = client.get("/investigations/CASE-710001/chat")
    assert history.status_code == 200
    messages = history.json()["messages"]
    assert len(messages) == 2
    assert messages[0]["case_id"] == "CASE-710001"


def test_chat_quick_action_and_clear(tmp_path, monkeypatch):
    database_module, main_module = _boot(tmp_path, monkeypatch)
    _create_case(database_module)

    client = TestClient(main_module.app)
    authenticate_client(client)

    quick = client.post(
        "/investigations/CASE-710001/chat",
        json={"message": "", "quick_action": "list_all_iocs"},
    )
    assert quick.status_code == 200
    assert quick.json()["quick_action"] == "list_all_iocs"

    before_clear = client.get("/investigations/CASE-710001/chat")
    assert before_clear.status_code == 200
    assert len(before_clear.json()["messages"]) >= 2

    cleared = client.delete("/investigations/CASE-710001/chat")
    assert cleared.status_code == 200
    assert cleared.json()["deleted"] >= 2

    after_clear = client.get("/investigations/CASE-710001/chat")
    assert after_clear.status_code == 200
    assert after_clear.json()["messages"] == []
