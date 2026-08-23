"""Telegram public-channel OSINT without API keys.

Uses the official web preview (t.me/s/<channel>) to pull channel metadata
(title, description, subscriber count) and recent posts. Also resolves
t.me/<username> user links.
"""
from __future__ import annotations

import re

from osintkit.core import Finding, HttpClient
from osintkit.modules.base import Module, register


@register
class TelegramModule(Module):
    name = "tg"
    help = "Public Telegram channel/user info via t.me/s preview"
    target_hint = "channel or username, e.g. some_channel"

    async def run(self, target: str, http: HttpClient) -> list[Finding]:
        target = target.lstrip("@").replace("https://t.me/", "")
        findings: list[Finding] = []
        body = await http.get_text(f"https://t.me/s/{target}")
        if 'tgme_widget_message' not in body:
            # probably a personal user link, not a channel
            status, _ = await http.head_or_get_status(f"https://t.me/{target}")
            if status == 200:
                findings.append(Finding(kind="profile", source=self.name,
                                        value=f"Telegram user alias '{target}' exists",
                                        confidence="medium",
                                        url=f"https://t.me/{target}"))
            return findings

        title_m = re.search(r'<span dir="auto">([^<]+)</span>', body)
        meta_m = re.search(r'tgme_page_extra">([^<]+)<', body)
        desc_m = re.search(r'tgme_page_description"[^>]*>(.*?)</div>', body, re.S)

        subs = ""
        if meta_m:
            subs = meta_m.group(1).strip()
        title = title_m.group(1).strip() if title_m else target

        findings.append(Finding(kind="channel", source=self.name,
                                value=f"Channel '{title}' — {subs}", confidence="high",
                                url=f"https://t.me/s/{target}",
                                extra={"description": _clean(desc_m.group(1)) if desc_m else ""}))

        posts = re.findall(
            r'tgme_widget_message_text[^>]*>(.*?)</div>', body, re.S)
        for i, p in enumerate(posts[-5:]):
            text = _clean(p)
            if text:
                findings.append(Finding(kind="post", source=self.name,
                                        value=text[:280], confidence="high",
                                        extra={"recency": f"last-{i+1}"}))
        return findings


def _clean(html: str) -> str:
    html = re.sub(r"<br/?>", "\n", html)
    html = re.sub(r"<[^>]+>", "", html)
    import html as html_mod
    return html_mod.unescape(html.replace("&nbsp;", " ")).strip()
