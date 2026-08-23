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
    Site("Steam", "https://steamcommunity.com/id/{}/", "The specified profile could not be found"),
    Site("Twitch", "https://m.twitch.tv/{}", "", "medium"),
    Site("SoundCloud", "https://soundcloud.com/{}", "", "medium"),
    Site("Pinterest", "https://www.pinterest.com/{}/", "", "medium"),
    Site("Flickr", "https://www.flickr.com/people/{}", "", "medium"),
    Site("DeviantArt", "https://www.deviantart.com/{}", "Not Found", "medium"),
    Site("Roblox", "https://www.roblox.com/users/profile?username={}", "", "low"),
    Site("Spotify", "https://open.spotify.com/user/{}", "", "medium"),
    Site("Mastodon (mastodon.social)", "https://mastodon.social/@{}", "The page you are looking for isn't here"),
]


@register
class UsernameModule(Module):
    name = "username"
    help = "Find profiles by username/handle across platforms"
    target_hint = "e.g. ivanov1990"

    async def run(self, target: str, http: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        handles = [target] + transliterate(target)
        for handle in handles:
            for site in SITES:
                url = site.url.replace("{}", handle)
                status, body = await http.head_or_get_status(url)
                if status == -1:
                    continue
                present = status == 200 and (
                    not site.not_found_marker or site.not_found_marker not in body
                )
                if present and site.not_found_marker == "" and status != 200:
                    present = False
                if present:
                    findings.append(Finding(
                        kind="profile",
                        source=f"{site.name} ({self.name})",
                        value=f"{site.name}: '{handle}' exists",
                        confidence=site.confidence,
                        url=url,
                        extra={"handle": handle},
                    ))
        return findings
