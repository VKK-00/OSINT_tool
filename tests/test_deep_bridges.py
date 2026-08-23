"""Offline tests for deep-integration bridge modules (osintkit-backed)."""
from __future__ import annotations

from osint_toolkit.engine import RunConfig, ScanTarget
from osint_toolkit.modules.deep_leaks import DeepLeaksModule
from osint_toolkit.modules.deep_sanctions import SanctionsIndexModule
from osint_toolkit.modules.dorks import DorksModule
from osint_toolkit.runtime import build_default_engine

CONFIG = RunConfig()


def test_dorks_generates_pivots():
    findings = DorksModule().scan(ScanTarget("username", "ivan_petrov"), CONFIG)
    assert any("socials" in (f.title or "") for f in findings)
    assert all(f.url.startswith("https://") for f in findings)


def test_sanctions_module_reports_empty_index(monkeypatch):
    mod = SanctionsIndexModule()
    res = mod.scan(ScanTarget("person", "nobody"), CONFIG)
    assert res[0].status in ("planned", "not_found", "hit")


def test_leaks_roundtrip(tmp_path, monkeypatch):
    from osintkit import store

    leak = tmp_path / "leak.txt"
    leak.write_text("someone@example.com:pass123\n", encoding="utf-8")
    store.import_leaks(str(leak))
    res = DeepLeaksModule().scan(ScanTarget("email", "someone@example.com"), CONFIG)
    assert any(f.status == "hit" for f in res)


def test_engine_includes_bridges():
    engine = build_default_engine()
    names = {m.name for m in engine.modules}
    assert {"sanctions-index", "deep-leaks", "dorks", "exif"} <= names


def test_sanctions_hit_builds_country_graph_edges():
    """A sanctions hit must yield country entities and person->country edges."""
    from osint_toolkit.engine import Finding, ScanTarget
    from osint_toolkit.entities import (
        entities_from_findings,
        entities_from_targets,
    )
    from osint_toolkit.graph import _edges_from_findings

    target = ScanTarget("person", "yanukovych")
    finding = Finding(
        module="sanctions-index", source="opensanctions-local",
        target="yanukovych", status="hit", confidence="medium",
        title="viktor yanukovych",
        metadata={"name": "viktor yanukovych", "country": "ru, ua"},
    )
    findings = (finding,)
    entities = (
        entities_from_targets((target,))
        + entities_from_findings(findings)
    )
    keys = {(e.kind, e.value) for e in entities}
    edges = _edges_from_findings((target,), findings, keys)
    relations = {e.relation for e in edges}
    assert "country_hint" in relations
    country_values = {e.target_value for e in edges if e.relation == "country_hint"}
    assert {"ru", "ua"} <= country_values


def test_exif_coordinates_entity():
    from osint_toolkit.engine import Finding
    from osint_toolkit.entities import entities_from_findings

    f = Finding(module="exif", source="exif-gps", target="http://x/i.jpg",
                status="hit", metadata={"coordinates": "50.450100,30.528400"})
    ents = entities_from_findings((f,))
    assert any(e.kind == "geo-coordinates" for e in ents)


def test_phone_native_still_works():
    from osint_toolkit.modules.phone import PhoneScanModule
    res = PhoneScanModule().scan(
        ScanTarget("phone", "+380501234567"),
        RunConfig(live=False))
    assert res
