import importlib
import json

from app.threat_intel_providers import VirusTotalProvider


class DummyClient:
    def __init__(self, payload):
        self.payload = payload

    def get_domain_report(self, domain):
        return self.payload

    def get_ip_report(self, ip):
        return self.payload

    def get_file_report(self, file_hash):
        return self.payload

    def get_url_report(self, url):
        return self.payload


def test_virustotal_provider_maps_data(monkeypatch):
    sample = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 96}, "last_analysis_date": 1620010000, "reputation": 22, "last_analysis_results": {"EngineA": {"category": "malicious", "result": "malicious"}}}}}

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "dummy")
    # monkeypatch the client used inside provider
    monkeypatch.setattr("app.threat_intel_providers.VirusTotalClient", lambda api_key: DummyClient(sample))

    provider = VirusTotalProvider()
    res = provider.enrich("example.com", "Domain")
    assert res["status"] == "ok"
    data = res["data"]
    assert data["malicious"] == 3
    assert "engine_verdicts" in data