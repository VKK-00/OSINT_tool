"""Telegram bot catalog enrichment via the keyless BotsArchive API."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient

BOTSARCHIVE_BOT_URL = "https://api.botsarchive.com/getBotID.php?username={username}"


def _json_dict(result):
    import json

    try:
        payload = json.loads(result.body_text)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


@dataclass(frozen=True)
class BotsArchiveModule:
    name: str = "botsarchive-bot"
    supported_targets: tuple[str, ...] = ("telegram", "username")

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        handle = target.value.strip().lstrip("@")
        if handle.startswith("https://t.me/"):
            handle = handle.rsplit("/", 1)[-1]
        url = BOTSARCHIVE_BOT_URL.format(username=quote("@" + handle, safe=""))
        if not config.live:
            return (
                Finding(
                    module=self.name, source="botsarchive-api", target=target.value,
                    status="planned", url=url, confidence="not_checked",
                    evidence="Dry run only. Pass --live to query the BotsArchive catalog.",
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        result = client.check(url)
        payload = _json_dict(result) if result.status_code == 200 else None
        if payload is None:
            return (
                Finding(
                    module=self.name, source="botsarchive-api", target=target.value,
                    status="unknown", http_status=result.status_code,
                    confidence="low",
                    evidence=result.error or f"HTTP {result.status_code} from BotsArchive.",
                ),
            )
        if not payload.get("ok"):
            return (
                Finding(
                    module=self.name, source="botsarchive-api", target=target.value,
                    status="not_found", http_status=200, confidence="medium",
                    evidence=f"Bot '@{handle}' is not present in the BotsArchive catalog.",
                ),
            )
        info = payload.get("result") or {}
        metadata = {
            "bot_username": str(info.get("username") or ("@" + handle)),
            "bot_name": str(info.get("name") or ""),
            "description": str(info.get("description") or "")[:300],
            "categories": ", ".join(info.get("category") or [])[:150],
            "groups_count": str(info.get("groups") or 0),
            "inline_mode": "yes" if info.get("inline") else "no",
            "archive_link": str(info.get("msg") or ""),
        }
        metadata = {k: v for k, v in metadata.items() if v}
        return (
            Finding(
                module=self.name, source="botsarchive-entry", target=target.value,
                status="candidate", url=str(info.get("msg") or url),
                http_status=200, confidence="medium",
                title=f"BotsArchive: {info.get('name') or handle}",
                evidence="Catalog entry for this Telegram bot in the community archive.",
                metadata=metadata,
            ),
        )
