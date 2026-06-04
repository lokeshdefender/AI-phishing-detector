import json
from pathlib import Path

REPORT = []


def add_report_entry(name: str, expected: str, actual: int):
    REPORT.append({"test": name, "expected": expected, "actual": actual})


def pytest_sessionfinish(session, exitstatus):
    out = Path(session.config.rootpath) / "tests" / "report.json"
    with out.open("w", encoding="utf-8") as f:
        json.dump(REPORT, f, indent=2)
    print(f"\nTest report written to: {out}")
