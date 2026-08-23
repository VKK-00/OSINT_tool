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


def test_phone_native_still_works():
    from osint_toolkit.modules.phone import PhoneScanModule
    res = PhoneScanModule().scan(
        ScanTarget("phone", "+380501234567"),
        RunConfig(live=False))
    assert res
