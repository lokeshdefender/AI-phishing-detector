import json
from pathlib import Path

from fastapi.testclient import TestClient

REPORT = []


def add_report_entry(name: str, expected: str, actual: int):
    REPORT.append({"test": name, "expected": expected, "actual": actual})


def pytest_sessionfinish(session, exitstatus):
    out = Path(session.config.rootpath) / "tests" / "report.json"
    with out.open("w", encoding="utf-8") as f:
        json.dump(REPORT, f, indent=2)
    print(f"\nTest report written to: {out}")


def authenticate_client(
    client: TestClient,
    *,
    email: str = "analyst@example.com",
    password: str = "Password123!",
    organization_name: str = "Test Org",
    role: str = "admin",
) -> dict:
    """Register and authenticate a test user for protected endpoint tests."""
    payload = {
        "email": email,
        "password": password,
        "organization_name": organization_name,
        "role": role,
        "full_name": "Test User",
    }
    register_response = client.post("/register", json=payload)
    if register_response.status_code == 409:
        login_response = client.post("/login", json={"email": email, "password": password})
        assert login_response.status_code == 200
        return login_response.json().get("user", {})

    assert register_response.status_code == 200
    return register_response.json().get("user", {})
