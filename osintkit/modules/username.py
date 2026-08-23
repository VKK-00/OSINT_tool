"""Username enumeration across social platforms (bridge -> osint_toolkit).

The site database (Sherlock/WhatsMyName/Maigret import + curated UA/RF
additions) and the per-site classification live in osint_toolkit now. This
legacy module keeps its UA/RF-weighted curated subset, transliterated handle
variants and the variant confidence downgrade — but delegates every HTTP
check to the unified engine module.
"""
from __future__ import annotations

import asyncio

from osintkit.bridge import build_run_config
from osintkit.core import Finding, HttpClient
from osintkit.modules.base import Module, register

# url_templates of the curated UA/RF-weighted subset (single source of sites:
# osint_toolkit.sites.USERNAME_SITES).
CURATED_TEMPLATES: tuple[str, ...] = (
    "https://vk.com/{username}",
    "https://ok.ru/{username}",
    "https://t.me/{username}",
    "https://habr.com/ru/users/{username}/",
    "https://dtf.ru/u/{username}",
    "https://career.habr.com/{username}",
    "https://github.com/{username}",
    "https://www.instagram.com/{username}/",
    "https://www.tiktok.com/@{username}",
    "https://x.com/{username}",
    "https://www.reddit.com/user/{username}",
    "https://www.youtube.com/@{username}",
    "https://steamcommunity.com/id/{username}/",
    "https://m.twitch.tv/{username}",
    "https://soundcloud.com/{username}",
    "https://www.pinterest.com/{username}/",
    "https://www.flickr.com/people/{username}/",
    "https://www.deviantart.com/{username}",
    "https://www.roblox.com/users/profile?username={username}",
    "https://open.spotify.com/user/{username}",
    "https://mastodon.social/@{username}",
    "https://gitlab.com/{username}",
    "https://medium.com/@{username}",
    "https://keybase.io/{username}",
    "https://www.last.fm/user/{username}",
)

_DOWNGRADE = {"high": "medium", "medium": "low", "low": "low"}


def curated_sites() -> tuple:
    """The curated UsernameSite subset, in CURATED_TEMPLATES order."""
    from osint_toolkit.sites import USERNAME_SITES

    by_template = {site.url_template: site for site in USERNAME_SITES}
    return tuple(by_template[t] for t in CURATED_TEMPLATES if t in by_template)


def _scan_handle(handle: str):
    from osint_toolkit.engine import ScanTarget
    from osint_toolkit.modules.username import UsernameScanModule

    config = build_run_config(min_request_delay=0.1)
    return UsernameScanModule(sites=curated_sites()).scan(
        ScanTarget(kind="username", value=handle), config)


@register
class UsernameModule(Module):
    name = "username"
    help = "Find profiles by username/handle across platforms"
    target_hint = "e.g. ivanov1990"

    def accepts(self, target: str) -> bool:
        value = target.strip()
        if "@" in value or value.lstrip("+").isdigit() or value.startswith("http"):
            return False
        return True

    async def run(self, target: str, http: HttpClient) -> list[Finding]:
        from osint_toolkit.translit import transliterate

        handles = [target] + transliterate(target)
        results_raw = await asyncio.gather(*[
            asyncio.to_thread(_scan_handle, handle) for handle in handles])

        out: list[Finding] = []
        variant_handles = set(handles[1:])
        for handle, engine_findings in zip(handles, results_raw, strict=True):
            is_variant = handle in variant_handles
            for item in engine_findings:
                if item.status != "candidate" or not item.source:
                    continue
                confidence = item.confidence
                if is_variant:
                    confidence = _DOWNGRADE.get(confidence, confidence)
                value = f"{item.source}: '{handle}' exists"
                title = item.title.strip()
                if title and "telegram" not in title.lower():
                    value += " — " + title[:120]
                extra = dict(item.metadata)
                extra["handle"] = handle
                if title:
                    extra["title"] = title[:120]
                out.append(Finding(
                    kind="profile",
                    source=f"{item.source} ({self.name})",
                    value=value,
                    confidence=confidence,
                    url=item.url,
                    extra=extra,
                ))
        return out
