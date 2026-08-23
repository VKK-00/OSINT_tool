"""Tests for the native module registry and module-level profile selection."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from osint_toolkit.engine import ScanTarget
from osint_toolkit.runtime import (
    MODULE_DESCRIPTOR_MAP,
    MODULE_DESCRIPTORS,
    build_default_engine,
)
from osint_toolkit.search import build_search_plan, parse_search_profiles


def test_every_engine_module_has_unique_descriptor():
    engine = build_default_engine()
    ids = [descriptor.module_id for descriptor in MODULE_DESCRIPTORS]
    assert len(ids) == len(set(ids))
    assert {m.name for m in engine.modules} == set(ids)


def test_descriptor_targets_match_instance():
    for descriptor in MODULE_DESCRIPTORS:
        assert descriptor.target_kinds == tuple(descriptor.instance.supported_targets)


def test_deep_modules_flagged_index_and_urlscan_key():
    deep = MODULE_DESCRIPTOR_MAP["deep-leaks"]
    sanctions = MODULE_DESCRIPTOR_MAP["sanctions-index"]
    urlscan = MODULE_DESCRIPTOR_MAP["urlscan-search"]
    dorks = MODULE_DESCRIPTOR_MAP["dorks"]

    assert deep.requires_index and deep.data_sensitivity == "breach_derived"
    assert sanctions.requires_index
    assert urlscan.requires_key and urlscan.key_env == "URLSCAN_API_KEY"
    assert not dorks.network_access and dorks.risk_tier == "passive"


def test_safe_profile_excludes_index_backed_modules():
    plan = build_search_plan("username", "example_user", profile_name="safe")
    selected = set(plan.profile.native_modules)
    assert "deep-leaks" not in selected
    assert "sanctions-index" not in selected
    assert "dorks" in selected


def test_person_full_runs_wikidata_but_not_leaks_or_dorks():
    profile_ids = set(build_search_plan("person", "Ivan Petrenko", profile_name="person-full").profile.native_modules)
    assert "wikidata-person" in profile_ids
    assert "person-name-expansion" in profile_ids
    assert "deep-leaks" not in profile_ids
    assert "sanctions-index" not in profile_ids
    assert "dorks" not in profile_ids


def test_allowed_native_modules_filters_execution():
    from osint_toolkit.investigation import run_investigation

    result = run_investigation(
        (ScanTarget(kind="email", value="person@example.com"),),
        allowed_native_modules=("dorks",),
    )
    modules = {finding.module for finding in result.findings}
    assert modules == {"dorks"}


def test_custom_profile_rejects_unknown_module_id():
    raw = json.dumps({
        "profiles": [{"name": "bad", "target_kinds": ["email"], "native_modules": ["no-such-module"]}]
    })
    with pytest.raises(ValueError, match="unknown module id"):
        parse_search_profiles(json.loads(raw))


def test_plan_shows_per_module_steps_with_readiness(monkeypatch):
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    plan = build_search_plan("domain", "example.com", profile_name="web-full")
    module_steps = {step.source: step for step in plan.steps if step.stage == "native"}
    assert "internetdb-ip" in module_steps
    assert "wayback-cdx" in module_steps
    urlscan = module_steps["urlscan-search"]
    assert urlscan.readiness == "config_missing"
    assert urlscan.metadata["requires_key"] == "true"
    wayback = module_steps["wayback-cdx"]
    assert wayback.readiness == "ready"


def test_modules_cli_command_lists_registry():
    r = subprocess.run(
        [sys.executable, "-m", "osint_toolkit", "modules", "--kind", "company"],
        capture_output=True, text=True, encoding="utf-8",
    )
    assert r.returncode == 0
    assert "gleif-company" in r.stdout
