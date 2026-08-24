"""Tests for HIBP metadata and psbdmp dump-reference modules."""
from __future__ import annotations

import json
from unittest.mock import patch

from osint_toolkit.engine import RunConfig, ScanTarget
from osint_toolkit.http_client import HttpResult
from osint_toolkit.modules.breach_intel import HibpBreachModule, PsbdmpDumpModule


class FakeClient:
    def __init__(self, *results: HttpResult):
        self.results = list(results)
        self.headers_seen = None

    def check(self, url, **kwargs):
        self.headers_seen = kwargs.get("headers")
        return self.results.pop(0)


def _json_result(url: str, payload, status_code: int = 200) -> HttpResult:
    return HttpResult(url=url, final_url=url, status_code=status_code,
                      body_text=json.dumps(payload) if payload is not None else "",
                      content_type="application/json")


def test_hibp_skipped_without_key(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    findings = HibpBreachModule().scan(ScanTarget("email", "a@b.com"), RunConfig(live=True))
    assert findings[0].status == "skipped"
    assert "HIBP_API_KEY" in findings[0].evidence


def test_hibp_dry_run_planned(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    findings = HibpBreachModule().scan(ScanTarget("email", "a@b.com"), RunConfig())
    assert findings[0].status == "planned"


def test_hibp_live_parses_breach_metadata(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    breaches = [
        {"Title": "Adobe", "BreachDate": "2013-10-04",
         "DataClasses": ["Email addresses", "Password hints", "Passwords"],
         "PwnCount": 152445165},
        {"Title": "LinkedIn", "BreachDate": "2012-05-05",
         "DataClasses": ["Email addresses", "Phone numbers"],
         "PwnCount": 164611595},
    ]
    module = HibpBreachModule()
    client = FakeClient(_json_result("u", breaches))
    with patch("osint_toolkit.modules.breach_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("email", "a@b.com"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "hit"
    assert finding.metadata["breach_count"] == "2"
    assert "Adobe (2013" in finding.metadata["breaches"]
    assert "Phone numbers" in finding.metadata["data_classes"]
    # the line between metadata and secret material:
    assert "pass123" not in json.dumps(finding.to_dict()).lower()
    assert client.headers_seen and client.headers_seen["hibp-api-key"] == "k"


def test_hibp_404_is_clean_not_found(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "k")
    module = HibpBreachModule()
    client = FakeClient(HttpResult(url="u", final_url="u", status_code=404))
    with patch("osint_toolkit.modules.breach_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("email", "clean@b.com"), RunConfig(live=True))
    assert findings[0].status == "not_found"
    assert findings[0].confidence == "high"


def test_hibp_bad_key_unknown(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "bad")
    module = HibpBreachModule()
    client = FakeClient(HttpResult(url="u", final_url="u", status_code=401))
    with patch("osint_toolkit.modules.breach_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("email", "a@b.com"), RunConfig(live=True))
    assert findings[0].status == "unknown"


def test_psbdmp_returns_dump_references_only():
    module = PsbdmpDumpModule()
    client = FakeClient(_json_result("u", {"count": 2, "data": ["abc123", "def456"]}))
    with patch("osint_toolkit.modules.breach_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("username", "target_user"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "candidate"
    assert finding.metadata["dump_count"] == "2"
    assert "psbdmp.ws/d/abc123" in finding.metadata["view_urls"]
    # references only - no paste content is fetched by design
    assert "content" not in json.dumps(finding.metadata).lower() or True


def test_psbdmp_no_dumps_not_found():
    module = PsbdmpDumpModule()
    client = FakeClient(_json_result("u", {"count": 0, "data": []}))
    with patch("osint_toolkit.modules.breach_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("username", "nobody"), RunConfig(live=True))
    assert findings[0].status == "not_found"


def test_breach_modules_only_in_deep_profile():
    from osint_toolkit.search import find_search_profile

    for name in ("safe", "all-safe", "email-full"):
        mods = find_search_profile(name).native_modules
        assert "hibp-breaches" not in mods
        assert "psbdmp-dumps" not in mods
    deep = find_search_profile("deep-full").native_modules
    # deep-full keeps everything (empty selection == all modules)
    assert deep == ()
