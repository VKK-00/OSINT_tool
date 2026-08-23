"""Username enumeration across social platforms (UA/RF-weighted site list).

Detection strategy per platform:
  * status-code based (404 => free, 200 => taken), plus
  * optional body heuristic (a "page not found" marker) to catch soft-404s.
"""
from __future__ import annotations

import dataclasses

from osintkit.core import Finding, HttpClient, transliterate
from osintkit.modules.base import Module, register


@dataclasses.dataclass
class Site:
    name: str
    url: str                 # {} replaced by handle
    not_found_marker: str = ""   # if this string is in the body -> profile absent
    confidence: str = "high"


SITES: list[Site] = [
    # --- UA/RF priority networks ---
    Site("VK", "https://vk.com/{}", "Страница не найдена"),
    Site("OK.ru", "https://ok.ru/{}", 'class="profile"'),
    Site("Telegram", "https://t.me/{}", "If you have Telegram, you can contact"),
    Site("Habr", "https://habr.com/ru/users/{}/", "Can't find"),
    Site("DTF", "https://dtf.ru/u/{}", ""),
    # --- Global majors ---
    Site("GitHub", "https://github.com/{}", "Not Found"),
    Site("Instagram", "https://www.instagram.com/{}/", "Page Not Found", "medium"),
    Site("TikTok", "https://www.tiktok.com/@{}", "", "medium"),
    Site("X/Twitter", "https://x.com/{}", "", "medium"),
    Site("Reddit", "https://www.reddit.com/user/{}/about.json", '"error": 404'),
    Site("YouTube", "https://www.youtube.com/@{}", "This page isn't available", "medium"),
    Site("Steam", "https://steamcommunity.com/id/{}/", "Steam Community :: Error"),
    Site("Twitch", "https://m.twitch.tv/{}", "", "low"),
    Site("SoundCloud", "https://soundcloud.com/{}", "", "medium"),
    Site("Pinterest", "https://www.pinterest.com/{}/", "", "medium"),
    Site("Flickr", "https://www.flickr.com/people/{}", "", "medium"),
    Site("DeviantArt", "https://www.deviantart.com/{}", "Not Found", "medium"),
    Site("Roblox", "https://www.roblox.com/users/profile?username={}", "", "low"),
    Site("Spotify", "https://open.spotify.com/user/{}", "", "medium"),
    Site("Mastodon (mastodon.social)", "https://mastodon.social/@{}", "The page you are looking for isn't here"),
    Site("GitLab", "https://gitlab.com/{}", ""),
    Site("Medium", "https://medium.com/@{}", ""),
    Site("Keybase", "https://keybase.io/{}", ""),
    Site("Last.fm", "https://www.last.fm/user/{}", "Whoops // Sorry, but something went wrong"),
    Site("Habr Career", "https://career.habr.com/{}", ""),
]


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
        import asyncio
        import re

        def enrich(site: Site, body: str) -> dict:
            """Pull og:title / page title from captured HTML when possible."""
            extra: dict = {}
            m = re.search(r'<meta property="og:title" content="([^"]*)"', body)
            if m and m.group(1).strip() and "telegram" not in m.group(1).lower():
                extra["title"] = m.group(1).strip()[:120]
            else:
                m2 = re.search(r"<title>([^<]{3,120})</title>", body)
                if m2 and site.name != "Telegram":
                    t = m2.group(1).strip()
                    if not re.search(r"not found|error", t, re.I):
                        extra["title"] = t[:120]
            return extra

        GENERIC_TITLES = {
            "twitch", "spotify – web player", "tiktok - make your day",
            "steam community :: error", "just a moment...", "page not found",
        }

        async def check(site: Site, handle: str):
            url = site.url.replace("{}", handle)
            status, body = await http.head_or_get_status(url)
            if status != 200:
                return None
            low_body = body.lower()
            if site.name == "Telegram":
                # t.me/<user> shows "contact @handle" both for existing users;
                # absence of the alias means nothing there.
                if ("@" + handle.lower()) not in low_body:
                    return None
            if site.not_found_marker and site.not_found_marker in body:
                return None
            extra = {"handle": handle}
            extra.update(enrich(site, body))
            title_low = extra.get("title", "").lower().strip()
            if title_low in GENERIC_TITLES:
                return None          # SPA shell / error page — not a profile
            value = f"{site.name}: '{handle}' exists"
            if extra.get("title"):
                value += " — " + extra["title"]
            return Finding(
                kind="profile",
                source=f"{site.name} ({self.name})",
                value=value,
                confidence=site.confidence,
                url=url,
                extra=extra,
            )

        handles = [target] + transliterate(target)
        results_raw = await asyncio.gather(*[
            check(s, h) for h in handles for s in SITES])
        out = []
        variant_handles = set(handles[1:])
        for r in results_raw:
            if r is None:
                continue
            if r.extra.get("handle") in variant_handles:
                r.confidence = {"high": "medium", "medium": "low",
                                "low": "low"}[r.confidence]
            out.append(r)
        return out
