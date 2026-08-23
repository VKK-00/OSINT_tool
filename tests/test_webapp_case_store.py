"""Offline tests: osintkit webapp persists scans into the shared case store."""
from __future__ import annotations

from osint_toolkit.case_store import CaseStore
from osintkit.bridge import core_to_engine
from osintkit.core import Finding, ModuleResult


def _module_result(target: str) -> ModuleResult:
    return ModuleResult(
        module="dorks",
        target=target,
        ok=True,
        findings=[
            Finding(
                kind="dork",
                source="dorks",
                value="Handle on UA/RF socials",
                confidence="low",
                url="https://www.google.com/search?q=x",
                extra={"yandex": "https://yandex.com/search/?text=x"},
            ),
            Finding(
                kind="lead",
                source="dorks",
                value=f"Pivot: Telegram alias check t.me/{target}",
                confidence="low",
                url=f"https://t.me/{target}",
            ),
        ],
    )


def test_core_to_engine_conversion():
    finding = Finding(kind="profile", source="GitHub", value="GitHub: 'x' exists",
                      confidence="medium", url="https://github.com/x")
    engine = core_to_engine(finding, target="x")
    assert engine.module == "GitHub"
    assert engine.status == "candidate"
    assert engine.confidence == "medium"
    assert engine.url == "https://github.com/x"


def test_webapp_scan_saves_into_shared_case_store(tmp_path, monkeypatch):
    import osintkit.webapp as webapp

    monkeypatch.chdir(tmp_path)
    case_id = webapp.save_case_from_results("ivan_petrov", [_module_result("ivan_petrov")])
    assert case_id and case_id.startswith("osintkit-")

    store = CaseStore(webapp.case_db_path())
    records = store.list_cases()
    assert len(records) == 1
    record = records[0]
    assert record.case_id == case_id
    assert record.finding_count >= 2

    detail = store.load_case(case_id)
    modules = {f["module"] for f in detail["findings"]}
    assert any("dorks" in module for module in modules)


def test_webapp_case_endpoints(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import osintkit.webapp as webapp

    monkeypatch.chdir(tmp_path)
    client = TestClient(webapp.app)
    empty = client.get("/api/cases")
    assert empty.status_code == 200
    assert empty.json() == {"cases": []}

    webapp.save_case_from_results("durov", [_module_result("durov")])
    listed = client.get("/api/cases")
    cases = listed.json()["cases"]
    assert len(cases) == 1

    detail = client.get(f"/api/cases/{cases[0]['case_id']}")
    assert detail.status_code == 200
    assert detail.json()["case"]["title"] == "osintkit scan: durov"

    missing = client.get("/api/cases/nope")
    assert missing.status_code == 404
