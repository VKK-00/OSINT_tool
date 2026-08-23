"""Search-engine dork builder: ready-to-click pivots for a target.

Purely generates deep-links (Google, Bing, DDG, Yandex) including RF/UA-
relevant site-scoped queries (vk.com, ok.ru, t.me, habr.com, pastebin...).
No scraping — the researcher clicks through manually.
"""
from __future__ import annotations

import urllib.parse

from osintkit.core import Finding, HttpClient, transliterate
from osintkit.modules.base import Module, register


def _q(engine: str, query: str) -> str:
    q = urllib.parse.quote(query)
    return {
        "google": "https://www.google.com/search?q=" + q,
        "yandex": "https://yandex.com/search/?text=" + q,
        "ddg": "https://duckduckgo.com/?q=" + q,
        "bing": "https://www.bing.com/search?q=" + q,
    }[engine]


@register
class DorksModule(Module):
    name = "dorks"
    help = "Ready-made search-engine dorks (incl. Yandex, VK, OK, pastebin)"
    target_hint = "any target"

    async def run(self, target: str, http: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        is_email = "@" in target
        is_phone = target.lstrip("+").isdigit()
        handle = target.split("@")[0] if is_email else target.strip("@")
        variants = [handle] + transliterate(handle)[:5]

        def add(label: str, engines: list[str], query: str) -> None:
            urls = {e: _q(e, query) for e in ("google", "yandex", "ddg", "bing")}
            primary = min(engines, key=lambda e: ["google", "yandex", "ddg", "bing"].index(e))
            findings.append(Finding(
                kind="dork", source=self.name,
                value=label + " (" + "+".join(engines) + ")",
                confidence="low",
                url=urls[primary],
                extra={k: v for k, v in urls.items() if k != primary}))

        if is_email:
            add('Exact email "' + target + '"', ["google", "yandex"], '"' + target + '"')
            add("Email on paste sites", ["google"],
                '"' + target + '" site:pastebin.com OR site:textbin.net')
            add("Email in dumps/combolists", ["google", "yandex"],
                '"' + target + '" filetype:txt OR filetype:csv')
        elif is_phone:
            p = target.lstrip("+")
            add('Phone exact "+' + p + '"', ["google", "yandex"],
                '"+"' + p + '" OR "' + p + '"')
            add("Phone on messengers/social", ["google", "yandex"],
                '"' + p + '" (site:t.me OR site:vk.com OR site:ok.ru OR site:wa.me)')
        else:
            v = " OR ".join([':"'+x+'"' for x in variants[:4]])
            add("Name/handle all variants", ["google", "yandex"], v)
            add("Handle on UA/RF socials", ["google", "yandex"],
                v + " (site:vk.com OR site:ok.ru OR site:t.me)")
            add("Handle on forums/blogs", ["yandex"],
                v + " (site:habr.com OR site:dtf.ru OR site:pikabu.ru)")
            add("Handle on paste sites", ["google"],
                v + " (site:pastebin.com OR site:textbin.net)")
            add("Documents mentioning target", ["google", "yandex"],
                v + " filetype:pdf")

        findings.append(Finding(
            kind="lead", source=self.name,
            value=f"Pivot: Telegram alias check t.me/{handle}",
            confidence="low",
            url=f"https://t.me/{handle}"))
        return findings
