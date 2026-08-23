"""Search-engine dork builder (bridge -> osint_toolkit.modules.dorks).

The link-building logic lives in the unified engine module; this legacy
module only delegates and converts results to osintkit report findings.
"""
from __future__ import annotations

from osintkit.bridge import build_run_config, core_confidence, engine_to_core, scan_target
from osintkit.core import Finding, HttpClient
from osintkit.modules.base import Module, register


@register
class DorksModule(Module):
    name = "dorks"
    help = "Ready-made search-engine dorks (incl. Yandex, VK, OK, pastebin)"
    target_hint = "any target"

    async def run(self, target: str, http: HttpClient) -> list[Finding]:
        from osint_toolkit.modules.dorks import DorksModule as EngineDorks

        engine_findings = EngineDorks().scan(scan_target(target), build_run_config())
        findings: list[Finding] = []
        for item in engine_findings:
            kind, extra = engine_to_core(item)
            if item.source == "lead":
                kind = "lead"
            else:
                kind = "dork"
            findings.append(Finding(
                kind=kind, source=self.name,
                value=item.title or item.evidence or item.url,
                confidence=core_confidence(item),
                url=item.url,
                extra=extra))
        return findings
