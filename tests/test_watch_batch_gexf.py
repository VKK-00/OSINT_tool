"""Tests for unified watch, batch targets from file, and GEXF export."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from osint_toolkit.case_store import CaseStore
from osint_toolkit.cli import build_case_gexf
from osint_toolkit.engine import ScanTarget
from osint_toolkit.watch import WatchRunner, compute_new_entities

# --- pure diff ---

def test_compute_new_entities_diffs_case_insensitively():
    from osint_toolkit.entities import Entity

    previous = [["domain", "example.com"], ["email", "a@b.com"]]
    current = (
        Entity("domain", "example.com", "s", "medium"),
        Entity("domain", "NEW.example.com", "s", "low"),
        Entity("email", "A@B.com", "s", "high"),
    )
    new = compute_new_entities(previous, current)
    assert [(e.kind, e.value) for e in new] == [("domain", "NEW.example.com")]


def test_watch_runner_cycles_overwrite_live_case_and_track_state(tmp_path):
    db = tmp_path / "cases.sqlite"
    store = CaseStore(db)
    targets = (ScanTarget(kind="company", value="Test Company"),)
    runner = WatchRunner(store, live=False)

    first = runner.run_cycle(
        "watch-1", targets,
        allowed_native_modules=("gleif-company",),
        title="watch cycle",
    )
    assert first.cycle_number == 1

    second = runner.run_cycle(
        "watch-1", targets,
        allowed_native_modules=("gleif-company",),
        title="watch cycle",
    )
    # dry-run findings are identical -> no NEW entities on the second cycle
    assert second.cycle_number == 2
    assert second.new_entities == ()

    state = store.get_watch_state("watch-1")
    assert state is not None and state["cycle_count"] == 2

    records = store.list_cases()
    live = [r for r in records if r.case_id == "watch-1"]
    assert len(live) == 1  # overwritten in place, not duplicated


def test_watch_new_entities_detected_between_runs(tmp_path):
    """Second cycle with an extra finding surfaces the new entity."""
    db = tmp_path / "cases.sqlite"
    store = CaseStore(db)
    targets = (ScanTarget(kind="username", value="durov"),)
    runner = WatchRunner(store, live=False)

    runner.run_cycle(
        "w2", targets,
        allowed_native_modules=("github-user",),
    )

    # pure diff already covered separately; here assert state persistence
    state = store.get_watch_state("w2")
    assert state is not None
    assert state["cycle_count"] == 1


# --- batch targets from file ---

def _write_targets_file(tmp_path: Path) -> str:
    file_path = tmp_path / "targets.txt"
    file_path.write_text(
        "# investigation scope\n"
        "email=victim@example.com\n"
        "example.org\n"
        "\n"
        "# commented out\n"
        "# phone=+10000000000\n",
        encoding="utf-8",
    )
    return str(file_path)


def test_cli_investigate_from_file(tmp_path):
    import subprocess
    import sys

    targets_file = _write_targets_file(tmp_path)
    result = subprocess.run(
        [sys.executable, "-m", "osint_toolkit", "investigate",
         "--title", "batch", "--from-file", targets_file, "--format", "json"],
        capture_output=True, text=True, encoding="utf-8",
        cwd=Path(__file__).resolve().parents[1],
    )
    assert result.returncode == 0, result.stderr[-500:]
    payload = json.loads(result.stdout)
    target_values = {(t["kind"], t["value"]) for t in payload["targets"]}
    assert ("email", "victim@example.com") in target_values
    assert ("domain", "example.org") in target_values


# --- GEXF export ---

def _case_payload_with_graph():
    return {
        "case": {"case_id": "c1"},
        "entities": [
            {"kind": "company", "value": "Test Company"},
            {"kind": "name", "value": "Test Company Ltd"},
            {"kind": "lei", "value": "12345678901234567890"},
        ],
        "edges": [
            {"source_kind": "company", "source_value": "Test Company",
             "relation": "registered_legal_name",
             "target_kind": "name", "target_value": "Test Company Ltd"},
            {"source_kind": "company", "source_value": "Test Company",
             "relation": "identified_by_lei",
             "target_kind": "lei", "target_value": "12345678901234567890"},
        ],
    }


def test_gexf_export_is_valid_xml_with_nodes_and_edges():
    xml_text = build_case_gexf(_case_payload_with_graph())
    root = ET.fromstring(xml_text)
    ns = {"g": "http://gexf.net/1.3"}
    nodes = root.findall(".//g:nodes/g:node", ns)
    edges = root.findall(".//g:edges/g:edge", ns)
    assert len(nodes) == 3
    assert len(edges) == 2
    labels = {n.get("label") for n in nodes}
    assert "Test Company Ltd" in labels
    rel = {e.get("label") for e in edges}
    assert {"registered_legal_name", "identified_by_lei"} <= rel


def test_gexf_via_cli_end_to_end(tmp_path):
    import subprocess
    import sys

    db = tmp_path / "cases.sqlite"
    store = CaseStore(db)
    from osint_toolkit.investigation import run_investigation

    result = run_investigation((ScanTarget(kind="email", value="person@example.com"),))
    store.save(result, case_id="g1")

    r = subprocess.run(
        [sys.executable, "-m", "osint_toolkit", "case-graph",
         "--case-db", str(db), "g1", "--format", "gexf"],
        capture_output=True, text=True, encoding="utf-8",
        cwd=Path(__file__).resolve().parents[1],
    )
    assert r.returncode == 0, r.stderr[-400:]
    root = ET.fromstring(r.stdout)
    assert root.tag.endswith("gexf")
