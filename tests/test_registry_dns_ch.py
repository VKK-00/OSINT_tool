"""Tests for passive-DNS and Companies House modules."""
from __future__ import annotations

import json
from unittest.mock import patch

from osint_toolkit.engine import RunConfig, ScanTarget
from osint_toolkit.http_client import HttpResult
from osint_toolkit.modules.company_intel import (
    CompaniesHouseModule,
    parse_companies_house,
)
from osint_toolkit.modules.domain_intel import PassiveDnsModule, parse_hackertarget_hostsearch


class FakeClient:
    def __init__(self, *results: HttpResult):
        self.results = list(results)

    def check(self, url, **kwargs):
        return self.results.pop(0)


def _json_result(url: str, payload) -> HttpResult:
    return HttpResult(
        url=url, final_url=url, status_code=200,
        body_text=json.dumps(payload), content_type="application/json",
    )


def _text_result(url: str, text: str, status_code: int = 200) -> HttpResult:
    return HttpResult(url=url, final_url=url, status_code=status_code,
                      body_text=text, content_type="text/plain")


def test_parse_hackertarget_hostsearch_filters_malformed():
    pairs = parse_hackertarget_hostsearch(
        "sub.example.com,1.2.3.4\nwww.example.com,1.2.3.4\nnocomma\nmail.example.com,5.6.7.8\n")
    assert ("sub.example.com", "1.2.3.4") in pairs
    assert len(pairs) == 3


def test_passive_dns_dry_run_planned():
    findings = PassiveDnsModule().scan(ScanTarget("domain", "example.com"), RunConfig())
    assert findings[0].status == "planned"


def test_passive_dns_live_parses_hosts():
    module = PassiveDnsModule()
    client = FakeClient(_text_result(
        "u", "sub.example.com,1.2.3.4\nwww.example.com,1.2.3.4\n"))
    with patch("osint_toolkit.modules.domain_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("domain", "example.com"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "candidate"
    assert finding.metadata["host_count"] == "2"
    assert "sub.example.com" in finding.metadata["subdomains"]
    assert finding.metadata["ips"] == "1.2.3.4"


def test_passive_dns_quota_exhausted_is_unknown_not_negative():
    module = PassiveDnsModule()
    client = FakeClient(_text_result("u", "Error! API count exceeded. Try again later."))
    with patch("osint_toolkit.modules.domain_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("domain", "example.com"), RunConfig(live=True))
    assert findings[0].status == "unknown"


def test_companies_house_skipped_without_key(monkeypatch):
    monkeypatch.delenv("COMPANIES_HOUSE_API_KEY", raising=False)
    findings = CompaniesHouseModule().scan(ScanTarget("company", "Acme Ltd"), RunConfig(live=True))
    assert findings[0].status == "skipped"
    assert "COMPANIES_HOUSE_API_KEY" in findings[0].evidence


def test_parse_companies_house_items():
    payload = {
        "items": [
            {
                "company_number": "00006400",
                "title": "BRITISH BROADCASTING CORPORATION",
                "company_status": "active",
                "company_type": "ltd",
                "date_of_creation": "1922-10-18",
                "address": {"premises": "Broadcasting House", "locality": "London",
                            "postal_code": "W1A 1AA", "country": "England"},
            }
        ]
    }
    companies = parse_companies_house(payload)
    assert companies[0]["company_number"] == "00006400"
    assert companies[0]["incorporated_at"] == "1922-10-18"
    assert "London" in companies[0]["address"]


def test_companies_house_live_sends_basic_auth(monkeypatch):
    monkeypatch.setenv("COMPANIES_HOUSE_API_KEY", "test-key")

    class RecordingClient(FakeClient):
        def __init__(self, result):
            super().__init__(result)
            self.headers_seen = None

        def check(self, url, **kwargs):
            self.headers_seen = kwargs.get("headers")
            return self.results.pop(0)

    import base64
    expected = base64.b64encode(b"test-key:").decode()
    payload = {"items": [{"company_number": "123", "title": "Test Co",
                          "company_status": "active"}]}
    client = RecordingClient(_json_result("u", payload))
    with patch("osint_toolkit.modules.company_intel._client", return_value=client):
        findings = CompaniesHouseModule().scan(ScanTarget("company", "Test Co"), RunConfig(live=True))
    assert client.headers_seen["Authorization"] == f"Basic {expected}"
    assert findings[0].status == "candidate"
    assert findings[0].metadata["legal_name"] == "Test Co"
