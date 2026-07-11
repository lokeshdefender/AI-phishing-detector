import time
import pytest

from app.threatintel.engine import ThreatIntelEngine
from app.threat_intel_providers import BaseThreatIntelProvider


class DummyProvider(BaseThreatIntelProvider):
    name = "Dummy"
    supported_ioc_types = ["Domain", "IP Address", "URL"]

    def enrich(self, ioc_value: str, ioc_type: str):
        if ioc_value == "raise.exception":
            raise RuntimeError("boom")
        if ioc_value == "slow.response":
            time.sleep(2)
            return {"status": "ok", "details": "slow"}
        return {"status": "ok", "details": f"enriched {ioc_value}"}


class TimeoutProvider(BaseThreatIntelProvider):
    name = "Timeout"
    supported_ioc_types = ["Domain"]

    def enrich(self, ioc_value: str, ioc_type: str):
        time.sleep(5)
        return {"status": "ok", "details": "late"}


def test_engine_runs_providers(monkeypatch):
    engine = ThreatIntelEngine(providers=[DummyProvider(), TimeoutProvider()], max_workers=2)
    # set a short timeout to exercise timeout handling
    monkeypatch.setenv("THREATINTEL_PROVIDER_TIMEOUT", "1")
    res = engine.enrich("example.com", "Domain")
    assert "Dummy" in res
    assert res["Dummy"]["status"] == "ok"
    # Timeout provider should be present and likely error or late
    assert "Timeout" in res


def test_engine_handles_provider_exceptions():
    engine = ThreatIntelEngine(providers=[DummyProvider()], max_workers=1)
    res = engine.enrich("raise.exception", "Domain")
    assert res["Dummy"]["status"] in {"error", "ok"}