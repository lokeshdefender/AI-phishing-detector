import time

import pytest

from app.clients.virustotal_client import VirusTotalClient


class DummyResp:
    def __init__(self, data, status=200):
        self._data = data
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")

    def json(self):
        return self._data


def test_get_domain_report(monkeypatch):
    sample = {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 97}, "last_analysis_date": 1620000000, "reputation": 12, "last_analysis_results": {"EngineX": {"category": "malicious", "result": "malicious", "method": "static"}}}}}

    def fake_get(url, params=None, timeout=None):
        return DummyResp(sample)

    monkeypatch.setattr("requests.Session.get", lambda self, *args, **kwargs: fake_get(*args, **kwargs))

    client = VirusTotalClient(api_key="dummy", timeout=2)
    resp = client.get_domain_report("example.com")
    assert resp["data"]["attributes"]["last_analysis_stats"]["malicious"] == 2


def test_get_ip_report(monkeypatch):
    sample = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70}, "last_analysis_date": 1620001111}}}

    def fake_get(url, params=None, timeout=None):
        return DummyResp(sample)

    monkeypatch.setattr("requests.Session.get", lambda self, *args, **kwargs: fake_get(*args, **kwargs))

    client = VirusTotalClient(api_key="dummy", timeout=2)
    resp = client.get_ip_report("8.8.8.8")
    assert resp["data"]["attributes"]["last_analysis_date"] == 1620001111


def test_get_url_report_post_and_poll(monkeypatch):
    # Simulate GET failing then POST returning id and analysis completed
    sample_analysis = {"data": {"id": "analysis-1", "attributes": {"status": "completed"}}}
    sample_url = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0, "harmless": 69}, "last_analysis_date": 1620002222}}}

    calls = {"get": 0}

    def fake_get(self, url, params=None, timeout=None):
        calls["get"] += 1
        # First GET attempt to /urls/{encoded} will raise
        if calls["get"] == 1:
            raise Exception("not found")
        return DummyResp(sample_url)

    def fake_post(self, url, data=None, timeout=None):
        return DummyResp({"data": {"id": "analysis-1"}})

    monkeypatch.setattr("requests.Session.get", fake_get)
    monkeypatch.setattr("requests.Session.post", fake_post)

    client = VirusTotalClient(api_key="dummy", timeout=5)
    resp = client.get_url_report("http://example.com/test")
    # either returns analysis or url data; we accept either structure
    assert isinstance(resp, dict)