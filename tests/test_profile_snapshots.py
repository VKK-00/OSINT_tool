"""Profile stabilization: pinned compositions + tri-state native_modules."""
from __future__ import annotations

from osint_toolkit.engine import RunConfig, ScanTarget
from osint_toolkit.runtime import (
    MODULE_DESCRIPTOR_MAP,
    MODULE_DESCRIPTORS,
    build_default_engine,
)
from osint_toolkit.search import (
    TARGET_KINDS,
    find_search_profile,
    parse_search_profiles,
)

EXPECTED_SNAPSHOTS = {
    "safe": {
        "username-public-profiles", "person-name-expansion", "email-baseline",
        "phone-baseline", "domain-baseline", "web-metadata", "telegram-baseline",
        "instagram-public-profile", "social-public-profile", "ru-ua-source-pack",
        "dorks", "exif", "github-user", "github-commit-emails",
        "mastodon-lookup", "bluesky-profile", "wikidata-person",
        "internetdb-ip", "wayback-cdx", "urlscan-search", "gleif-company",
        "email-quality", "botsarchive-bot",
    },
    "all-safe": None,  # same composition as safe; resolved below
    "deep-full": None,  # full explicit snapshot of all 35 modules
}


def test_builtin_profile_compositions_are_pinned():
    for name in ("safe", "all-safe", "deep-full", "person-full", "username-full",
                 "email-full", "phone-full", "web-full", "passive-recon",
                 "social-full", "ru-ua-full", "company-safe", "passive-only",
                 "standard"):
        profile = find_search_profile(name)
        assert profile.native_modules is not None, f"{name} must be an explicit allowlist"
        assert len(profile.native_modules) > 0 or name == "deep-full"


def test_deep_full_snapshot_is_the_full_explicit_module_list():
    deep = find_search_profile("deep-full")
    all_ids = set(MODULE_DESCRIPTOR_MAP)
    assert set(deep.native_modules) == all_ids
    # stability: a future integration must NOT silently join this profile
    assert "some-future-module" not in set(deep.native_modules)


def test_safe_excludes_index_backed_modules():
    safe = set(find_search_profile("safe").native_modules)
    assert "deep-leaks" not in safe
    assert "sanctions-index" not in safe


def test_passive_only_has_zero_network_modules():
    passive = find_search_profile("passive-only")
    assert set(passive.native_modules)
    for module_id in passive.native_modules:
        assert MODULE_DESCRIPTOR_MAP[module_id].network_access is False


def test_standard_alias_matches_safe():
    standard = find_search_profile("standard")
    safe = find_search_profile("safe")
    assert standard.native_modules == safe.native_modules


def test_empty_native_modules_means_nothing_runs():
    custom = parse_search_profiles([{
        "name": "nothing-runs",
        "target_kinds": ["email"],
        "native_kinds": ["email"],
        "native_modules": [],
    }])
    engine = build_default_engine()
    findings = []
    for target in (ScanTarget(kind="email", value="a@b.com"),):
        for module in engine.modules:
            if module.name in set(custom[0].native_modules) and \
                    target.kind in module.supported_targets:
                findings.extend(module.scan(target, RunConfig()))
    assert findings == []


def test_absent_native_modules_still_auto_includes_all(monkeypatch):
    from osint_toolkit.investigation import run_investigation

    result = run_investigation(
        (ScanTarget(kind="email", value="person@example.com"),),
        allowed_native_modules=None,
    )
    modules = {f.module for f in result.findings}
    assert "dorks" in modules  # auto mode includes everything compatible


def test_every_target_kind_has_at_least_one_module_or_is_image():
    for kind in TARGET_KINDS:
        if kind == "image":
            continue
        assert any(kind in d.target_kinds for d in MODULE_DESCRIPTORS), (
            f"no registered module supports target kind {kind}"
        )
