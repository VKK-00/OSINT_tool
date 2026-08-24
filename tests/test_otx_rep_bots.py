"""Tests for OTX reputation and BotsArchive modules."""
from __future__ import annotations

import json
from unittest.mock import patch

from osint_toolkit.engine import RunConfig, ScanTarget
from osint_toolkit.http_client import HttpResult
from osint_toolkit.modules.domain_intel import OtxReputationModule
from osint_toolkit.modules.telegram_intel import BotsArchiveModule


class FakeClient:
    def __init__(self, *results: HttpResult):
        self.results = list(results)
        self.headers_seen = None

    def check(self, url, **kwargs):
        self.headers_seen = kwargs.get("headers")
        return self.results.pop(0)


def _json_result(url: str, payload) -> HttpResult:
    return HttpResult(url=url, final_url=url, status_code=200,
                      body_text=json.dumps(payload), content_type="application/json")


def test_otx_reputation_parses_pulses(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "k")
    payload = {"pulse_info": {"count": 7, "pulses": [
        {"name": "Malicious domain feed", "tags": ["malware"], "adversary": "BotnetX"},
        {"name": "Phishing list 2026", "tags": ["phishing"]},
    ]}}
    module = OtxReputationModule()
    client = FakeClient(_json_result("u", payload))
    with patch("osint_toolkit.modules.domain_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("domain", "bad.example"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "candidate"
    assert finding.metadata["pulse_count"] == "7"
    assert "Malicious domain feed" in finding.metadata["pulse_names"]
    assert finding.metadata["adversaries"] == "BotnetX"
    assert finding.confidence == "high"  # >= 5 pulses


def test_otx_reputation_no_pulses_not_found(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "k")
    module = OtxReputationModule()
    client = FakeClient(_json_result("u", {"pulse_info": {"count": 0, "pulses": []}}))
    with patch("osint_toolkit.modules.domain_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("domain", "clean.example"), RunConfig(live=True))
    assert findings[0].status == "not_found"


def test_botsarchive_parses_catalog_entry():
    payload = {
        "ok": 1,
        "id": 1,
        "result": {
            "id": 1,
            "name": "Votebot",
            "username": "@vote",
            "description": "Official Telegram poll bot.",
            "category": ["poll"],
            "groups": 3,
            "inline": 1,
            "msg": "http://t.me/BotsArchive/79",
        },
    }
    module = BotsArchiveModule()
    client = FakeClient(_json_result("u", payload))
    with patch("osint_toolkit.modules.telegram_intel.HttpClient", return_value=client):
        findings = module.scan(
            ScanTarget("telegram", "@vote"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "candidate"
    assert finding.metadata["bot_name"] == "Votebot"
    assert finding.metadata["categories"] == "poll"
    assert finding.metadata["inline_mode"] == "yes"


def test_botsarchive_missing_bot_not_found():
    module = BotsArchiveModule()
    client = FakeClient(_json_result("u", {"ok": 0, "message": "bot not found"}))
    with patch("osint_toolkit.modules.telegram_intel.HttpClient", return_value=client):
        findings = module.scan(
            ScanTarget("username", "@nonexistent_xyz"), RunConfig(live=True))
    assert findings[0].status == "not_found"


def test_botsarchive_accepts_tme_url_and_strips_handle():
    module = BotsArchiveModule()
    client = FakeClient(_json_result("u", {"ok": 0, "message": "bot not found"}))
    with patch("osint_toolkit.modules.telegram_intel.HttpClient", return_value=client):
        findings = module.scan(
            ScanTarget("telegram", "https://t.me/somebot"), RunConfig(live=True))
    # reached the API (not invalid) - normalizer extracted 'somebot'
    assert findings[0].status in {"not_found", "unknown"}
