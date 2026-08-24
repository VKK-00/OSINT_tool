"""Regression tests for the evidence-integrity fixes from the second review."""
from __future__ import annotations

from osint_toolkit.engine import Finding, RunConfig, ScanTarget
from osint_toolkit.entities import (
    EVIDENCE_STATUSES,
    NON_EVIDENCE_STATUSES,
    entities_from_findings,
    is_evidence_finding,
)
from osint_toolkit.graph import graph_edges_from_case
from osint_toolkit.investigation import run_investigation


def test_status_sets_are_strict_complement():
    assert not (EVIDENCE_STATUSES & NON_EVIDENCE_STATUSES)
    assert "planned" in NON_EVIDENCE_STATUSES
    assert "candidate" in EVIDENCE_STATUSES


def test_dorks_findings_are_probes_not_evidence():
    """Generated search URLs are probes: never evidence, never graph nodes."""
    from osint_toolkit.modules.dorks import DorksModule

    findings = DorksModule().scan(ScanTarget("email", "person@example.com"), RunConfig())
    assert findings and all(f.status == "planned" for f in findings)

    assert not is_evidence_finding(findings[0])
    assert entities_from_findings(tuple(findings)) == ()


def test_no_generated_search_url_reaches_graph_edges():
    """Review regression: a generated search URL must never appear as an edge."""
    targets = (ScanTarget(kind="email", value="person@example.com"),)
    result = run_investigation(
        targets,
        allowed_native_modules=("dorks",),
        title="dork probe case",
    )
    assert result.findings, "dorks module should still emit probe findings"
    assert all(f.status == "planned" for f in result.findings)

    url_values = {
        entity.value.lower()
        for entity in result.entities
        if entity.kind == "url"
    }
    assert not any("google.com/search" in v for v in url_values), (
        "generated search URLs leaked into the evidence graph"
    )
    for edge in result.edges:
        combined = f"{edge.source_value} {edge.target_value}".lower()
        assert "google.com/search" not in combined


def test_unknown_status_fails_closed():
    finding = Finding(
        module="some-new-source", source="api", target="x",
        status="totally_new_status_made_up",  # typo / future integration
        url="https://example.com/profile",
        confidence="high",
    )
    assert not is_evidence_finding(finding)
    assert entities_from_findings((finding,)) == ()


def test_bridge_core_to_engine_restores_recorded_status():
    from osintkit.bridge import core_to_engine
    from osintkit.core import Finding as CoreFinding

    recorded = CoreFinding(
        kind="profile", source="GitHub", value="exists",
        confidence="medium", url="https://github.com/x",
        extra={"status": "candidate"},
    )
    restored = core_to_engine(recorded, target="x")
    assert restored.status == "candidate"

    unrecorded = CoreFinding(kind="profile", source="X", value="v",
                             confidence="medium", url="")
    degraded = core_to_engine(unrecorded, target="x")
    assert degraded.status == "unknown"  # fail-closed, not candidate

    planned = CoreFinding(kind="profile", source="Y", value="probe",
                          confidence="low", url="https://y",
                          extra={"status": "planned"})
    kept_planned = core_to_engine(planned, target="x")
    assert kept_planned.status == "planned"


def test_graph_edges_from_case_fail_closed_on_unknown_status():
    finding = Finding(
        module="mystery", source="src", target="t",
        status="brand_new_integration_status",
        metadata={"domain": "evil.example"},
    )
    targets = (ScanTarget(kind="domain", value="t"),)
    assert entities_from_findings((finding,)) == ()
    edges = graph_edges_from_case(targets, (finding,), ())
    assert () == tuple(e for e in edges if e.target_value == "evil.example")
