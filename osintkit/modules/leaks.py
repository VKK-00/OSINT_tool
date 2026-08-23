"""Search user-supplied local leak datasets (offline, sqlite index).

Import first:  osintkit leaks-import <file-or-dir>
Then scan:     osintkit scan -m leaks "ivan_petrov"
"""
from __future__ import annotations

from osintkit.core import Finding
from osintkit.modules.base import Module, register
from osintkit import store


@register
class LeaksModule(Module):
    name = "leaks"
    help = "Local leak-dataset search (import first: leaks-import)"
    target_hint = "email / username / phone digits"

    async def run(self, target: str, http) -> list[Finding]:
        findings = [
            Finding(kind="lead", source=self.name,
                    value="No local leak index — run 'osintkit leaks-import <path>'",
                    confidence="low")
        ] if not store.DB_PATH.exists() else []
        hits = store.search_leaks(target)
        if not hits and findings:
            return findings
        findings = findings if (not hits and findings) else []
        by_source: dict[str, list] = {}
        for h in hits[:50]:
            by_source.setdefault(h["source"] or "unknown", []).append(h)
        for src, items in sorted(by_source.items()):
            kinds = ", ".join(sorted({i["kind"] for i in items}))
            sample = items[0]["value"]
            findings.append(Finding(
                kind="exposure", source=self.name,
                value=f"{len(items)} hit(s) · {kinds} · in {src} · e.g. '{sample}'",
                confidence="high",
                extra={"matches": [i["value"] for i in items[:20]]}))
        return findings
