"""Telegram public-channel OSINT (bridge -> osint_toolkit.modules.telegram).

Channel parsing, recent posts and the bounded ?before= history crawl live in
the unified engine module now; this legacy module only delegates and converts
results to osintkit report findings.
"""
from __future__ import annotations

from osintkit.bridge import build_run_config, core_confidence, engine_to_core
from osintkit.core import Finding, HttpClient
from osintkit.modules.base import Module, register


@register
class TelegramModule(Module):
    name = "tg"
    help = "Public Telegram channel info + history crawl via t.me/s preview"
    target_hint = "channel or username, e.g. some_channel"

    def accepts(self, target: str) -> bool:
        value = target.strip()
        if "@" in value and "." in value.split("@")[-1]:
            return False          # looks like an email
        if value.lstrip("+").isdigit():
            return False          # phone number
        return True

    async def run(self, target: str, http: HttpClient) -> list[Finding]:
        from osint_toolkit.engine import ScanTarget
        from osint_toolkit.modules.telegram import TelegramScanModule

        handle = target.strip().lstrip("@").replace("https://t.me/", "")
        engine_findings = TelegramScanModule().scan(
            ScanTarget(kind="telegram", value=handle), build_run_config())
        findings: list[Finding] = []
        for item in engine_findings:
            if item.status not in {"candidate", "hit"}:
                continue
            kind, extra = engine_to_core(item)
            findings.append(Finding(
                kind=kind, source=self.name,
                value=item.title or item.evidence,
                confidence=core_confidence(item),
                url=item.url,
                extra=extra))
        return findings
