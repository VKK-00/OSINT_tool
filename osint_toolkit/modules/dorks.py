"""Ready-to-click search-engine dorks (Google/Yandex/DDG/Bing).

Pure link generation — no requests are made. Yandex included deliberately:
it indexes runet far better than Google, which matters for RU/UA targets.
"""
from __future__ import annotations

import urllib.parse

from ..engine import Finding, RunConfig, ScanTarget


def _q(engine: str, query: str) -> str:
    q = urllib.parse.quote(query)
    return {
        "google": "https://www.google.com/search?q=" + q,
        "yandex": "https://yandex.com/search/?text=" + q,
        "ddg": "https://duckduckgo.com/?q=" + q,
        "bing": "https://www.bing.com/search?q=" + q,
    }[engine]


class DorksModule:
    name = "dorks"
    supported_targets = ("username", "email", "phone", "person", "domain",
                         "url", "telegram", "instagram", "social", "ru-ua")

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        value = target.value.strip()
        findings: list[Finding] = []

        def add(label: str, query: str) -> None:
            findings.append(Finding(
                module=self.name, source="dork", target=target.value,
                status="candidate", confidence="low",
                url=_q("google", query), title=label,
                metadata={
                    "yandex": _q("yandex", query),
                    "ddg": _q("ddg", query),
                    "bing": _q("bing", query),
                }))

        if "@" in value:
            add('Exact email "' + value + '"', '"' + value + '"')
            add("Email on paste sites",
                f'"{value}" (site:pastebin.com OR site:textbin.net)')
            add("Email in dumps/txt-csv",
                f'"{value}" filetype:txt OR filetype:csv')
        elif value.lstrip("+").isdigit():
            p = value.lstrip("+")
            add(f'Phone exact "+{p}"', f'"+"{p}" OR "{p}"')
            add("Phone on messengers/socials",
                f'"{p}" (site:t.me OR site:vk.com OR site:ok.ru OR site:wa.me)')
        else:
            v = " OR ".join([f'"{value}"', f'"{value.lower()}"'])
            add("Handle/name variants", v)
            add("Handle on UA/RF socials",
                v + " (site:vk.com OR site:ok.ru OR site:t.me)")
            add("Handle on forums/blogs",
                v + " (site:habr.com OR site:dtf.ru OR site:pikabu.ru)")
            add("Documents mentioning target", v + " filetype:pdf")
        return tuple(findings)
