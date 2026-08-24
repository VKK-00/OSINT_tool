"""Tests for ip-api, DomainsDB and email-quality enrichment modules."""
from __future__ import annotations

import json
from unittest.mock import patch

from osint_toolkit.engine import RunConfig, ScanTarget
from osint_toolkit.http_client import HttpResult
from osint_toolkit.modules.domain_intel import DomainsdbSearchModule, IpGeoModule
from osint_toolkit.modules.email_intel import EmailQualityModule


class FakeClient:
    def __init__(self, *results: HttpResult):
        self.results = list(results)

    def check(self, url, **kwargs):
        return self.results.pop(0)


def _json_result(url: str, payload) -> HttpResult:
    return HttpResult(url=url, final_url=url, status_code=200,
                      body_text=json.dumps(payload), content_type="application/json")


def test_ip_geo_dry_run_planned():
    findings = IpGeoModule().scan(ScanTarget("domain", "example.com"), RunConfig())
    assert findings[0].status == "planned"


def test_ip_geo_live_parses_network_ownership(monkeypatch):
    monkeypatch.setattr(
        "osint_toolkit.modules.domain_intel._resolve_ipv4",
        lambda host: "93.184.216.34")
    payload = {
        "status": "success", "query": "93.184.216.34",
        "country": "United States", "countryCode": "US",
        "regionName": "Virginia", "city": "Norfolk",
        "lat": 36.85, "lon": -76.28, "isp": "Verizon", "org": "Edgecast",
        "as": "AS15133", "asname": "EDGECAST", "reverse": "example.com",
        "mobile": False, "proxy": False, "hosting": True,
    }
    module = IpGeoModule()
    client = FakeClient(_json_result("http://ip-api.com/json/93.184.216.34", payload))
    with patch("osint_toolkit.modules.domain_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("domain", "example.com"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "candidate"
    assert finding.metadata["isp"] == "Verizon"
    assert finding.metadata["as"] == "AS15133"
    assert finding.metadata["is_hosting"] == "yes"
    assert finding.metadata["country_code"] == "US"
    assert "Norfolk" in finding.title


def test_ip_geo_unresolvable_is_not_found(monkeypatch):
    monkeypatch.setattr(
        "osint_toolkit.modules.domain_intel._resolve_ipv4", lambda host: None)
    findings = IpGeoModule().scan(ScanTarget("domain", "nope.invalid"), RunConfig(live=True))
    assert findings[0].status == "not_found"


def test_domainsdb_rejects_short_words():
    findings = DomainsdbSearchModule().scan(ScanTarget("company", "ab"), RunConfig())
    assert findings[0].status == "invalid"


def test_domainsdb_live_parses_results():
    payload = {
        "total": 2,
        "domains": [
            {"domain": "acme.com", "create_date": "1995-01-01"},
            {"domain": "acme.io", "create_date": "2010-05-05"},
        ],
    }
    module = DomainsdbSearchModule()
    client = FakeClient(_json_result("u", payload))
    with patch("osint_toolkit.modules.domain_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("company", "Acme Ltd!"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "candidate"
    assert finding.metadata["search_word"] == "acmeltd"
    assert "acme.com" in finding.metadata["sample_domains"]


def test_email_quality_dry_run_planned():
    findings = EmailQualityModule().scan(ScanTarget("email", "a@b.com"), RunConfig())
    assert findings[0].status == "planned"


def test_email_quality_combines_eva_and_kickbox():
    eva_payload = {"status": "success", "data": {
        "result": "deliverable", "free": True, "disposable": False, "role_account": False}}
    kickbox_payload = {"disposable": False}
    module = EmailQualityModule()
    client = FakeClient(
        _json_result("eva", eva_payload),
        _json_result("kb", kickbox_payload),
    )
    with patch("osint_toolkit.modules.email_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("email", "user@gmail.com"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "candidate"
    assert finding.confidence == "medium"
    assert finding.metadata["eva_disposable"] == "false"
    assert finding.metadata["kickbox_disposable"] == "false"
    assert "deliverable" in finding.title


def test_email_quality_disposable_flagged():
    eva_payload = {"status": "success", "data": {"result": "undeliverable", "disposable": True}}
    kickbox_payload = {"disposable": True}
    module = EmailQualityModule()
    client = FakeClient(_json_result("eva", eva_payload), _json_result("kb", kickbox_payload))
    with patch("osint_toolkit.modules.email_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("email", "x@mailinator.com"), RunConfig(live=True))
    assert findings[0].metadata["kickbox_disposable"] == "true"
    assert findings[0].confidence == "low"


def test_email_quality_both_sources_down_is_unknown():
    module = EmailQualityModule()
    client = FakeClient(
        HttpResult(url="e", final_url="e", status_code=503),
        HttpResult(url="k", final_url="k", status_code=503),
    )
    with patch("osint_toolkit.modules.email_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("email", "a@b.com"), RunConfig(live=True))
    assert findings[0].status == "unknown"
