"""Tests for CourtListener search, OTX passive DNS and new experimental adapters."""
from __future__ import annotations

import json
from unittest.mock import patch

from osint_toolkit.adapters import find_adapter
from osint_toolkit.engine import RunConfig, ScanTarget
from osint_toolkit.http_client import HttpResult
from osint_toolkit.modules.domain_intel import OtxPassiveDnsModule
from osint_toolkit.modules.legal_intel import CourtListenerModule


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


# --- CourtListener ---

def test_courtlistener_skipped_without_key(monkeypatch):
    monkeypatch.delenv("COURTLISTENER_API_KEY", raising=False)
    findings = CourtListenerModule().scan(ScanTarget("company", "Acme Ltd"), RunConfig(live=True))
    assert findings[0].status == "skipped"
    assert "COURTLISTENER_API_KEY" in findings[0].evidence


def test_courtlistener_invalid_query():
    findings = CourtListenerModule().scan(ScanTarget("company", "ab"), RunConfig(live=True))
    assert findings[0].status == "invalid"


def test_courtlistener_live_parses_documents(monkeypatch):
    monkeypatch.setenv("COURTLISTENER_API_KEY", "tok")
    payload = {"count": 1, "results": [{
        "caseName": "United States v. Example Corp",
        "court_citation_string": "S.D.N.Y.",
        "docketNumber": "1:21-cr-00555",
        "dateFiled": "2021-11-03",
        "absolute_url": "/opinion/12345/us-v-example/",
        "snippet": "<b>Example</b> Corp wire fraud count one",
    }]}
    module = CourtListenerModule()
    client = FakeClient(_json_result("u", payload))
    with patch("osint_toolkit.modules.legal_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("company", "Example Corp"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "candidate"
    assert finding.metadata["case_name"] == "United States v. Example Corp"
    assert finding.metadata["docket_number"] == "1:21-cr-00555"
    assert "<b>" not in finding.metadata["snippet"]
    assert client.headers_seen["Authorization"] == "Token tok"


def test_courtlistener_no_results_not_found(monkeypatch):
    monkeypatch.setenv("COURTLISTENER_API_KEY", "tok")
    module = CourtListenerModule()
    client = FakeClient(_json_result("u", {"count": 0, "results": []}))
    with patch("osint_toolkit.modules.legal_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("person", "Nobody Name"), RunConfig(live=True))
    assert findings[0].status == "not_found"


# --- OTX passive DNS ---

def test_otx_skipped_without_key(monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    findings = OtxPassiveDnsModule().scan(ScanTarget("domain", "example.com"), RunConfig(live=True))
    assert findings[0].status == "skipped"


def test_otx_live_parses_history(monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "k")
    payload = {"passive_dns": [
        {"hostname": "www.example.com", "address": "1.2.3.4", "last": "2026-01-05T00:00:00"},
        {"hostname": "api.example.com", "address": "5.6.7.8", "last": "2025-12-01T00:00:00"},
    ]}
    module = OtxPassiveDnsModule()
    client = FakeClient(_json_result("u", payload))
    with patch("osint_toolkit.modules.domain_intel.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("domain", "example.com"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "candidate"
    assert finding.metadata["record_count"] == "2"
    assert finding.metadata["latest_seen"] == "2026-01-05"
    assert client.headers_seen == {"X-OTX-API-KEY": "k"}


# --- experimental adapters ---

def test_reconng_and_autoarchiver_registered_with_env_gating():
    recon = find_adapter("lanmaster53/recon-ng")
    aa = find_adapter("bellingcat/auto-archiver")
    assert recon.target_kinds == ("domain",)
    assert aa.target_kinds == ("url",)
    assert "RECONNG_RESOURCE" in recon.optional_env
    assert "AUTOARCHIVER_CONFIG" in aa.required_env


def test_reconng_command_renders_from_env(monkeypatch):
    from osint_toolkit.adapters import find_adapter

    monkeypatch.setenv("RECONNG_BIN", "/opt/recon-ng/recon-ng")
    monkeypatch.setenv("RECONNG_WORKSPACE", "/tmp/ws")
    monkeypatch.setenv("RECONNG_RESOURCE", "/tmp/run.rc")
    cmd = find_adapter("lanmaster53/recon-ng").render_command(
        ScanTarget(kind="domain", value="example.com"))
    assert cmd[:4] == ("/opt/recon-ng/recon-ng", "-w", "/tmp/ws", "--no-verbose")
    assert "-r" in cmd and "/tmp/run.rc" in cmd
