"""Tests for concurrent username scanning and company graph signals."""
from __future__ import annotations

import threading
from unittest.mock import patch

from osint_toolkit.engine import Engine, RunConfig, ScanTarget
from osint_toolkit.entities import entities_from_findings
from osint_toolkit.graph import graph_edges_from_case
from osint_toolkit.http_client import HttpResult
from osint_toolkit.modules.username import UsernameScanModule
from osint_toolkit.sites import UsernameSite


class SlowFakeClient:
    """Serializes request timestamps to prove parallel execution."""

    def __init__(self, sites_count: int):
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.remaining = sites_count

    def check(self, url, **kwargs):
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        import time

        time.sleep(0.05)
        with self.lock:
            self.active -= 1
            self.remaining -= 1
        return HttpResult(url=url, final_url=url, status_code=200,
                          title="ok", content_type="text/html")


def _sites(n: int) -> tuple[UsernameSite, ...]:
    return tuple(
        UsernameSite(f"Site{i}", f"https://s{i}.example/{{username}}")
        for i in range(n)
    )


def test_username_scan_parallel_matches_sequential_output():
    module = UsernameScanModule(sites=_sites(6))

    def make_client():
        return SlowFakeClient(6)

    with patch("osint_toolkit.modules.username.HttpClient", side_effect=lambda **kw: make_client()):
        seq = Engine([module]).scan(ScanTarget("username", "user1"), RunConfig(live=True))
    with patch("osint_toolkit.modules.username.HttpClient", side_effect=lambda **kw: make_client()):
        par = Engine([module]).scan(
            ScanTarget("username", "user1"), RunConfig(live=True, http_workers=3))

    assert [(f.source, f.status) for f in seq] == [(f.source, f.status) for f in par]
    assert len(par) == 6


def test_username_scan_parallel_actually_overlaps():
    module = UsernameScanModule(sites=_sites(4))
    client = SlowFakeClient(4)
    with patch("osint_toolkit.modules.username.HttpClient", return_value=client):
        Engine([module]).scan(ScanTarget("username", "user1"),
                              RunConfig(live=True, http_workers=4, request_delay=0))
    assert client.max_active > 1


def test_gleif_finding_builds_company_graph_signals():
    from osint_toolkit.engine import Finding
    from osint_toolkit.entities import entities_from_targets, merge_entities

    finding = Finding(
        module="gleif-company", source="gleif-entity", target="Test Company",
        status="candidate",
        metadata={
            "legal_name": "Test Company Ltd",
            "lei": "12345678901234567890",
            "status": "ACTIVE",
        },
    )
    targets = (ScanTarget(kind="company", value="Test Company"),)
    entities = merge_entities(
        entities_from_targets(targets), entities_from_findings((finding,)))
    keys = {(e.kind, e.value.lower()) for e in entities}
    assert ("name", "test company ltd") in keys
    assert ("lei", "12345678901234567890") in keys

    edges = graph_edges_from_case(targets, (finding,), entities)
    relations = {edge.relation for edge in edges}
    assert {"registered_legal_name", "identified_by_lei"} <= relations
