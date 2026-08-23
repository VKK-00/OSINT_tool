"""Telegram public-channel OSINT without API keys.

Uses the official web preview (t.me/s/<channel>) to pull channel metadata,
recent posts, and — via ?before=<id> pagination — up to a few hundred
messages of public history. Also resolves t.me/<username> user links.
"""
from __future__ import annotations

import re

from osintkit.core import Finding, HttpClient
from osintkit.modules.base import Module, register


def _avg(values: list) -> str:
    nums = []
    for v in values:
        try:
            nums.append(float(str(v).replace("K", "000").replace("M", "000000")))
        except (ValueError, TypeError):
            pass
    return f"{sum(nums)/len(nums):,.0f}" if nums else "-"


def _extract_posts(body: str) -> list[dict]:
    """Pull structured posts from a t.me/s page."""
    posts = []
    blocks = re.findall(
        r'<div class="tgme_widget_message[\s\S]*?(?=<div class="tgme_widget_message |$)',
        body)
    for b in blocks:
        id_m = re.search(r'data-post="[^"]*?/(\d+)"', b)
        date_m = re.search(r'<time datetime="([^"]+)"', b)
        views_m = re.search(r'tgme_widget_message_views">([^<]+)<', b)
        text_m = re.search(r'tgme_widget_message_text[^>]*>([\s\S]*?)</div>', b)
        posts.append({
            "num": int(id_m.group(1)) if id_m else 0,
            "id": id_m.group(0).split("/")[-1].rstrip('"') if id_m else "",
            "date": (date_m.group(1)[:16] if date_m else ""),
            "views": (views_m.group(1).strip() if views_m else ""),
            "text": text_m.group(1) if text_m else "",
        })
    return [p for p in posts if p["num"]]


@register
class TelegramModule(Module):
    name = "tg"
    help = "Public Telegram channel info + history crawl via t.me/s preview"
    target_hint = "channel or username, e.g. some_channel"

    async def run(self, target: str, http: HttpClient) -> list[Finding]:
        target = target.lstrip("@").replace("https://t.me/", "")
        findings: list[Finding] = []
        body = await http.get_text(f"https://t.me/s/{target}")
        if 'tgme_widget_message' not in body:
            status, _ = await http.head_or_get_status(f"https://t.me/{target}")
            if status == 200:
                findings.append(Finding(kind="profile", source=self.name,
                                        value=f"Telegram user alias '{target}' exists",
                                        confidence="medium",
                                        url=f"https://t.me/{target}"))
            return findings

        title_m = re.search(r'<span dir="auto">([^<]+)</span>', body)
        meta_m = re.search(r'tgme_page_extra">([^<]+)<', body)
        desc_m = re.search(r'tgme_page_description"[^>]*(.*?)</div>', body, re.S)

        subs = meta_m.group(1).strip() if meta_m else ""
        title = title_m.group(1).strip() if title_m else target

        findings.append(Finding(kind="channel", source=self.name,
                                value=f"Channel '{title}' — {subs}", confidence="high",
                                url=f"https://t.me/s/{target}",
                                extra={"description": _clean(desc_m.group(1)) if desc_m else ""}))

        posts = _extract_posts(body)
        recent = posts[-5:]
        for i, p in enumerate(recent):
            text = _clean(p["text"])
            if text:
                extra = {"recency": f"last-{i+1}"}
                if p["date"]:
                    extra["date"] = p["date"]
                if p["views"]:
                    extra["views"] = p["views"]
                findings.append(Finding(kind="post", source=self.name,
                                        value=text[:280], confidence="high",
                                        extra=extra))

        # ---- history crawl via ?before=<id> (no API keys needed) ----
        if posts:
            seen_ids: set[str] = set()
            history: list[dict] = []
            for p in posts:
                if p["text"] and p["id"] and p["id"] not in seen_ids:
                    seen_ids.add(p["id"])
                    history.append({"id": p["id"], "date": p["date"],
                                    "views": p["views"],
                                    "text": _clean(p["text"])[:160]})
            oldest = min((p["num"] for p in posts), default=0)
            for _page in range(4):          # ~5 pages x ~20 posts total
                if not oldest:
                    break
                try:
                    page_body = await http.get_text(
                        f"https://t.me/s/{target}?before={oldest}")
                    page_posts = _extract_posts(page_body)
                except Exception:
                    break
                fresh = 0
                for p in page_posts:
                    if p["text"] and p["id"] and p["id"] not in seen_ids:
                        seen_ids.add(p["id"])
                        history.append({"id": p["id"], "date": p["date"],
                                        "views": p["views"],
                                        "text": _clean(p["text"])[:160]})
                        fresh += 1
                new_oldest = min((p["num"] for p in page_posts), default=0)
                if not new_oldest or new_oldest >= oldest:
                    break
                oldest = new_oldest
                if fresh == 0:
                    break

            if history:
                findings.append(Finding(
                    kind="history", source=self.name,
                    value=f"Public history crawled: {len(history)} messages "
                          f"(avg views: {_avg([h['views'] for h in history])})",
                    confidence="high",
                    url=f"https://t.me/s/{target}",
                    extra={"messages": history[:60]}))
        return findings


def _clean(html_src: str) -> str:
    import html as html_mod
    html_src = re.sub(r"<br/?>", "\n", html_src)
    html_src = re.sub(r"<[^>]+>", "", html_src)
    return html_mod.unescape(html_src.replace("&nbsp;", " ")).strip()
