"""Contract sweep: every registered module must behave per the status contract.

Covers the second-review stabilization ask: a future module that emits a typo
status or leaks evidence during dry-run fails here, before it ever reaches a
case graph.
"""
from __future__ import annotations

import pytest

from osint_toolkit.engine import Engine, RunConfig, ScanTarget
from osint_toolkit.entities import EVIDENCE_STATUSES, NON_EVIDENCE_STATUSES
from osint_toolkit.runtime import MODULE_DESCRIPTORS

KNOWN_STATUSES = EVIDENCE_STATUSES | NON_EVIDENCE_STATUSES

SEEDS = {
    "person": "Ivan Petrenko",
    "username": "example_user",
    "email": "person@example.com",
    "phone": "+380501234567",
    "domain": "example.com",
    "url": "https://example.com/",
    "telegram": "@durov",
    "instagram": "@exampleuser",
    "social": "vk:exampleuser",
    "ru-ua": "all",
    "company": "Test Company",
}


@pytest.mark.parametrize(
    "descriptor",
    MODULE_DESCRIPTORS,
    ids=lambda d: d.module_id,
)
def test_every_module_dry_run_respects_status_contract(descriptor):
    if not descriptor.target_kinds:
        pytest.skip("module declares no target kinds")
    kind = descriptor.target_kinds[0]
    module = descriptor.instance
    findings = Engine([module]).scan(
        ScanTarget(kind=kind, value=SEEDS.get(kind, "example_value")),
        RunConfig(live=False),
    )
    if not findings:
        return  # nothing produced in dry-run for this seed - allowed

    # 1. every emitted status is a documented contract status
    unknown_statuses = {f.status for f in findings} - KNOWN_STATUSES
    assert not unknown_statuses, (
        f"{descriptor.module_id} emitted undocumented status(es): {unknown_statuses}"
    )

    # 2. network-backed modules may only emit offline-derived evidence in a
    #    dry run: local analysis (syntax, local-part, normalization) is fine,
    #    but such findings must carry NO http_status (no request happened)
    if descriptor.network_access and not descriptor.dry_run_evidence:
        for finding in findings:
            if finding.status in EVIDENCE_STATUSES:
                assert finding.http_status is None, (
                    f"{descriptor.module_id} emitted evidence finding with an "
                    f"HTTP status {finding.http_status} during dry-run "
                    f"(source={finding.source})"
                )

    # 3. offline generators marked dry_run_evidence are expected to assert
    if descriptor.dry_run_evidence:
        evidence = {f.status for f in findings} & EVIDENCE_STATUSES
        assert evidence, (
            f"{descriptor.module_id} is marked dry_run_evidence but emitted "
            "no evidence statuses in dry-run"
        )


def test_catalog_of_documented_statuses_is_complete():
    """Every status stored anywhere in a case DB comes from contract sets."""
    # cross-check: metadata probe against a quick scan of the whole engine
    engine = Engine([d.instance for d in MODULE_DESCRIPTORS])
    seen: set[str] = set()
    config = RunConfig(live=False)
    for kind, value in SEEDS.items():
        for finding in engine.scan(ScanTarget(kind=kind, value=value), config):
            seen.add(finding.status)
    unknown = seen - KNOWN_STATUSES
    assert not unknown, f"undocumented statuses observed: {unknown}"
