"""Offline tests for domain/IP intelligence modules (InternetDB, CDX, urlScan)."""
from __future__ import annotations

import json
from unittest.mock import patch

from osint_toolkit.engine import RunConfig, ScanTarget
from osint_toolkit.http_client import HttpResult
from osint_toolkit.modules.domain_intel import (
    InternetDbModule,
    UrlscanSearchModule,
    WaybackCdxModule,
    _host_of,
)


class FakeClient:
    def __init__(self, *results: HttpResult):
        self.results = list(results)
        self.requests: list[str] = []

    def check(self, url, **kwargs):
        self.requests.append(url)
        if len(self.results) == 1:
            return self.results[0]
        return self.results.pop(0)


def _json_result(url: str, payload) -> HttpResult:
    return HttpResult(
        url=url, final_url=url, status_code=200,
        body_text=json.dumps(payload), content_type="application/json",
    )


def test_host_of_strips_scheme_www_and_path():
    assert _host_of("https://www.example.com/a?b") == "example.com"
    assert _host_of("http://user:pass@Example.com:8080/x") == "example.com"
    assert _host_of("example.com") == "example.com"


def test_internetdb_dry_run_planned():
    findings = InternetDbModule().scan(ScanTarget("domain", "example.com"), RunConfig())
    assert findings[0].status == "planned"


def test_internetdb_live_parses_exposure():
    payload = {
        "ip": "93.184.216.34", "ports": [80, 443],
        "hostnames": ["www.example.com"], "cpes": [], "vulns": ["CVE-2021-44228"],
    }
    module = InternetDbModule()
    client = FakeClient(_json_result("https://internetdb.shodan.io/93.184.216.34", payload))
    with (
        patch("osint_toolkit.modules.domain_intel._resolve_ipv4", return_value="93.184.216.34"),
        patch("osint_toolkit.modules.domain_intel.HttpClient", return_value=client),
    ):
        findings = module.scan(ScanTarget("domain", "example.com"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "candidate"
    assert finding.metadata["queried_host"] == "example.com"
    assert finding.metadata["ports"] == "80, 443"
    assert finding.metadata["vulnerabilities"] == "CVE-2021-44228"
    assert finding.title.endswith("2 open ports, 1 known CVEs")


def test_internetdb_unresolvable_domain_not_found(monkeypatch):
    monkeypatch.setattr(
        "osint_toolkit.modules.domain_intel._resolve_ipv4", lambda host: None)
    findings = InternetDbModule().scan(ScanTarget("domain", "nope.invalid"), RunConfig(live=True))
    assert findings[0].status == "not_found"


def _cdx_result(url: str, rows) -> HttpResult:
    return _json_result(url, [["timestamp", "original"], *rows])


def test_wayback_cdx_reports_age_bounds():
    module = WaybackCdxModule()
    client = FakeClient(
        _cdx_result("earliest-url", [["19970101000000", "http://example.com/"]]),
        _cdx_result("latest-url", [["20260615000000", "https://example.com/"]]),
    )
    with patch("osint_toolkit.modules.domain_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("domain", "example.com"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "candidate"
    assert finding.metadata["earliest_snapshot"] == "19970101000000"
    assert finding.metadata["latest_snapshot"] == "20260615000000"
    assert finding.metadata["observed_age_years"] == "30"
    assert len(client.requests) == 2


def test_wayback_cdx_no_snapshots():
    module = WaybackCdxModule()
    client = FakeClient(
        _json_result("u1", []),  # empty CDX response -> header row missing
        _json_result("u2", []),
    )
    with patch("osint_toolkit.modules.domain_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("url", "https://example.com/deep/path"), RunConfig(live=True))
    assert findings[0].status == "not_found"


def test_urlscan_skipped_without_key(monkeypatch):
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    findings = UrlscanSearchModule().scan(ScanTarget("domain", "example.com"), RunConfig(live=True))
    assert findings[0].status == "skipped"
    assert "URLSCAN_API_KEY" in findings[0].evidence


def test_urlscan_live_parses_history(monkeypatch):
    monkeypatch.setenv("URLSCAN_API_KEY", "test-key")
    payload = {
        "total": 2,
        "results": [
            {"page": {"url": "https://example.com/", "ip": "93.184.216.34"},
             "task": {"time": "2026-06-01T10:00:00Z"}},
            {"page": {"url": "https://example.com/about"},
             "task": {"time": "2025-01-01T09:00:00Z"}},
        ],
    }

    class RecordingClient(FakeClient):
        def __init__(self, *args):
            super().__init__(*args)
            self.headers_seen = None

        def check(self, url, **kwargs):
            self.headers_seen = kwargs.get("headers")
            return self.results.pop(0)

    client = RecordingClient(_json_result("u", payload))
    with patch("osint_toolkit.modules.domain_intel.HttpClient", return_value=client):
        findings = UrlscanSearchModule().scan(ScanTarget("domain", "example.com"), RunConfig(live=True))
    assert client.headers_seen == {"API-Key": "test-key"}
    finding = findings[0]
    assert finding.status == "candidate"
    assert finding.metadata["total_scans"] == "2"
    assert "93.184.216.34" in finding.metadata["recent_scans"]


def test_ru_ua_source_pack_includes_public_registries():
    from osint_toolkit.engine import Engine
    from osint_toolkit.modules.ru_ua_sources import RuUaSourcePackModule

    engine = Engine([RuUaSourcePackModule()])
    findings = engine.scan(
        ScanTarget(kind="ru-ua", value="public-registry", region="ua"), RunConfig())
    names = {f.source for f in findings}
    assert {"UA Court Register", "UA EDR Open Data"} <= names
    assert "RF EGRUL/EGRIP" not in names
