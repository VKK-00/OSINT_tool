"""Tests for the PredictaSearch keyed reverse-lookup module."""
from __future__ import annotations

import json
from unittest.mock import patch

from osint_toolkit.engine import RunConfig, ScanTarget
from osint_toolkit.http_client import HttpResult
from osint_toolkit.modules.person_sources import PredictasearchModule


class FakeClient:
    def __init__(self, result: HttpResult):
        self.result = result
        self.headers_seen = None
        self.body_seen = None
        self.method_seen = None

    def check(self, url, **kwargs):
        self.headers_seen = kwargs.get("headers")
        self.body_seen = kwargs.get("body")
        self.method_seen = kwargs.get("method")
        return self.result


def _json_result(payload, status_code: int = 200) -> HttpResult:
    return HttpResult(url="u", final_url="u", status_code=status_code,
                      body_text=json.dumps(payload), content_type="application/json")


def test_skipped_without_key(monkeypatch):
    monkeypatch.delenv("PREDICTASEARCH_API_KEY", raising=False)
    findings = PredictasearchModule().scan(
        ScanTarget("email", "a@b.com"), RunConfig(live=True))
    assert findings[0].status == "skipped"
    assert "PREDICTASEARCH_API_KEY" in findings[0].evidence


def test_dry_run_planned(monkeypatch):
    monkeypatch.setenv("PREDICTASEARCH_API_KEY", "k")
    findings = PredictasearchModule().scan(ScanTarget("email", "a@b.com"), RunConfig())
    assert findings[0].status == "planned"


def test_live_sends_documented_request_shape(monkeypatch):
    monkeypatch.setenv("PREDICTASEARCH_API_KEY", "tok")
    client = FakeClient(_json_result({"people": []}))
    with patch("osint_toolkit.modules.person_sources.HttpClient", return_value=client):
        PredictasearchModule().scan(ScanTarget("phone", "+380501234567"), RunConfig(live=True))
    assert client.method_seen == "POST"
    body = json.loads(client.body_seen)
    assert body["query"] == "+380501234567"
    assert body["query_type"] == "phone"       # derived from target kind
    assert body["networks"] == ["all"]
    assert client.headers_seen["x-api-key"] == "tok"


def test_live_people_found(monkeypatch):
    monkeypatch.setenv("PREDICTASEARCH_API_KEY", "tok")
    people = [
        {"network": "twitter", "url": "https://twitter.com/x"},
        {"network": "chess", "url": "https://chess.com/member/x"},
    ]
    module = PredictasearchModule()
    client = FakeClient(_json_result({"people": people}))
    with patch("osint_toolkit.modules.person_sources.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("username", "someuser"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "candidate"
    assert finding.metadata["people_count"] == "2"
    assert finding.metadata["networks"] == "chess, twitter"


def test_live_no_people_not_found(monkeypatch):
    monkeypatch.setenv("PREDICTASEARCH_API_KEY", "tok")
    module = PredictasearchModule()
    client = FakeClient(_json_result({"people": []}))
    with patch("osint_toolkit.modules.person_sources.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("email", "a@b.com"), RunConfig(live=True))
    assert findings[0].status == "not_found"


def test_bad_key_unknown(monkeypatch):
    monkeypatch.setenv("PREDICTASEARCH_API_KEY", "bad")
    module = PredictasearchModule()
    client = FakeClient(HttpResult(url="u", final_url="u", status_code=401))
    with patch("osint_toolkit.modules.person_sources.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("email", "a@b.com"), RunConfig(live=True))
    assert findings[0].status == "unknown"
