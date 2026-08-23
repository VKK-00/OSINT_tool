"""Sanctions / watchlist search over a local OpenSanctions simplecsv index.

Build the index once:  osintkit sanctions-update   (~100 MB download)
Or from a local CSV:   osintkit sanctions-update --file path.csv
Then:                  osintkit scan -m sanctions "ivanov"
"""
from __future__ import annotations

from osintkit.core import Finding
from osintkit.modules.base import Module, register
from osintkit import store


@register
class SanctionsModule(Module):
    name = "sanctions"
    help = "Sanctions/watchlist match by name (local OpenSanctions index)"
    target_hint = "person or entity name"

    async def run(self, target: str, http) -> list[Finding]:
        if not store.sanctions_ready():
            return [Finding(kind="lead", source=self.name,
                            value="Index empty — run 'osintkit sanctions-update'",
                            confidence="low")]
        hits = store.search_sanctions(target)
        findings = []
        for h in hits:
            bits = [b for b in (h["schema"], h["countries"], h["topics"],
                                h["birth_date"]) if b]
            value = h["name"] + (" · " + " · ".join(bits) if bits else "")
            if h["notes"]:
                value += "\n" + h["notes"][:300]
            findings.append(Finding(kind="sanctions", source=self.name,
                                    value=value.strip(), confidence="medium",
                                    url=f"https://www.opensanctions.org/search/?q={h['name']}"))
        if not hits:
            findings.append(Finding(kind="sanctions", source=self.name,
                                    value="No watchlist matches", confidence="low"))
        return findings
