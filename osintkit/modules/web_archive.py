"""Web archiving helpers — the golden rule of OSINT is ARCHIVE FIRST.

* Wayback Machine availability lookup
* Trigger a Save-Page-Now capture
"""
from __future__ import annotations

import urllib.parse

from osintkit.core import Finding, HttpClient
from osintkit.modules.base import Module, register


@register
class ArchiveModule(Module):
    name = "archive"
    help = "Wayback snapshot lookup + trigger a fresh capture"
    target_hint = "URL to check/archive"

    def accepts(self, target: str) -> bool:
        return target.lower().startswith(("http://", "https://"))

    async def run(self, target: str, http: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        url = urllib.parse.quote(target, safe=":/?&=%")

        try:
            avail = await http.get_json(
                f"http://archive.org/wayback/available?url={url}")
            snap = (avail.get("archived_snapshots") or {}).get("closest") or {}
            if snap.get("available"):
                ts = snap.get("timestamp", "")
                pretty = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
                findings.append(Finding(kind="archive", source=self.name,
                                        value=f"Snapshot from {pretty}",
                                        confidence="high", url=snap.get("url", "")))
            else:
                findings.append(Finding(kind="archive", source=self.name,
                                        value="No existing snapshot", confidence="medium"))
        except Exception as exc:
            findings.append(Finding(kind="archive", source=self.name,
                                    value=f"Availability check failed: {exc}", confidence="low"))

        if not target.lower().startswith(("http://", "https://")):
            findings.append(Finding(kind="archive", source=self.name,
                                    value="Not a URL — skipped Save-Page-Now",
                                    confidence="low"))
            return findings

        try:
            await http.get_text(f"https://web.archive.org/save/{url}")
            findings.append(Finding(kind="archive", source=self.name,
                                    value="Save-Page-Now triggered",
                                    confidence="high",
                                    url=f"https://web.archive.org/web/*/{target}"))
        except Exception as exc:
            findings.append(Finding(kind="archive", source=self.name,
                                    value=f"SPN failed (may still succeed server-side): {exc}",
                                    confidence="low"))
        return findings
