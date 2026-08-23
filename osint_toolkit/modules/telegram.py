from __future__ import annotations

import html as html_mod
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient

HANDLE_RE = re.compile(r"^[A-Za-z0-9_]{5,32}$")

HISTORY_CRAWL_PAGES = 4  # ~5 pages x ~20 posts total
RECENT_POSTS_SHOWN = 5


@dataclass(frozen=True)
class TelegramScanModule:
    name: str = "telegram-baseline"
    supported_targets: tuple[str, ...] = ("telegram",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        parsed = normalize_telegram_target(target.value)
        if not parsed:
            return (
                Finding(
                    module=self.name,
                    source="normalizer",
                    target=target.value,
                    status="invalid",
                    confidence="high",
                    evidence="Could not normalize input into a public Telegram handle or t.me URL.",
                ),
            )

        url, target_type = parsed
        if not config.live:
            return (
                Finding(
                    module=self.name,
                    source="telegram-url",
                    target=target.value,
                    status="planned",
                    url=url,
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to fetch public t.me metadata.",
                    metadata={"target_type": target_type},
                ),
            )

        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent)
        handle = urlparse(url).path.strip("/") if target_type == "handle" else ""
        if target_type == "handle" and handle:
            return scan_telegram_channel(handle, client, target=target.value)
        result = client.check(url, fetch_title=True)
        status = "candidate" if result.status_code and result.status_code < 400 else "unknown"
        return (
            Finding(
                module=self.name,
                source="telegram-url",
                target=target.value,
                status=status,
                url=result.final_url or url,
                title=result.title,
                http_status=result.status_code,
                confidence="medium" if result.status_code and result.status_code < 400 else "low",
                evidence=result.error or f"HTTP {result.status_code}",
                metadata={"target_type": target_type, "content_type": result.content_type},
            ),
        )


def normalize_telegram_target(value: str) -> tuple[str, str] | None:
    raw = value.strip()
    if not raw:
        return None
    if raw.startswith("@"):
        raw = raw[1:]
    if HANDLE_RE.match(raw):
        return f"https://t.me/{raw}", "handle"

    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if parsed.netloc.lower() not in {"t.me", "telegram.me", "telegram.dog"}:
        return None
    path = parsed.path.strip("/")
    if not path:
        return None
    parts = path.split("/")
    handle = parts[0]
    if handle.startswith("+"):
        return f"https://t.me/{path}", "invite_or_private_link"
    if not HANDLE_RE.match(handle):
        return None
    if len(parts) >= 2 and parts[1].isdigit():
        return f"https://t.me/{handle}/{parts[1]}", "post"
    return f"https://t.me/{handle}", "handle"


# --- public channel preview (t.me/s/<handle>) parsing -----------------------


def clean_html_fragment(html_src: str) -> str:
    html_src = re.sub(r"<br/?>", "\n", html_src)
    html_src = re.sub(r"<[^>]+>", "", html_src)
    return html_mod.unescape(html_src.replace("&nbsp;", " ")).strip()


def extract_channel_posts(body: str) -> list[dict[str, object]]:
    """Pull structured posts from a t.me/s channel preview page."""
    posts: list[dict[str, object]] = []
    blocks = re.findall(
        r'<div class="tgme_widget_message[\s\S]*?(?=<div class="tgme_widget_message |$)',
        body)
    for block in blocks:
        id_m = re.search(r'data-post="[^"]*?/(\d+)"', block)
        date_m = re.search(r'<time datetime="([^"]+)"', block)
        views_m = re.search(r'tgme_widget_message_views">([^<]+)<', block)
        text_m = re.search(r'tgme_widget_message_text[^>]*>([\s\S]*?)</div>', block)
        posts.append({
            "num": int(id_m.group(1)) if id_m else 0,
            "id": id_m.group(0).split("/")[-1].rstrip('"') if id_m else "",
            "date": date_m.group(1)[:16] if date_m else "",
            "views": views_m.group(1).strip() if views_m else "",
            "text": text_m.group(1) if text_m else "",
        })
    return [p for p in posts if p["num"]]


def parse_channel_page(body: str) -> dict[str, object] | None:
    """Return channel header fields if the page is a t.me/s channel preview."""
    if "tgme_widget_message" not in body:
        return None
    title_m = re.search(r'<span dir="auto">([^<]+)</span>', body)
    meta_m = re.search(r'tgme_page_extra">([^<]+)<', body)
    desc_m = re.search(r'tgme_page_description"[^>]*(.*?)</div>', body, re.S)
    return {
        "title": title_m.group(1).strip() if title_m else "",
        "subscribers": meta_m.group(1).strip() if meta_m else "",
        "description": clean_html_fragment(desc_m.group(1)) if desc_m else "",
    }


def average_views(values: list[object]) -> str:
    nums: list[float] = []
    for value in values:
        try:
            nums.append(float(str(value).replace("K", "000").replace("M", "000000")))
        except (ValueError, TypeError):
            continue
    return f"{sum(nums) / len(nums):,.0f}" if nums else "-"


def crawl_channel_history(handle: str, client: HttpClient, posts: list[dict[str, object]]) -> list[dict[str, object]]:
    """Walk ?before=<id> pagination of the public preview; no API keys needed."""
    seen_ids: set[str] = set()
    history: list[dict[str, object]] = []
    for post in posts:
        if post["text"] and post["id"] and post["id"] not in seen_ids:
            seen_ids.add(str(post["id"]))
            history.append({
                "id": post["id"], "date": post["date"],
                "views": post["views"],
                "text": clean_html_fragment(str(post["text"]))[:160],
            })
    oldest = min((int(p["num"]) for p in posts), default=0)
    for _page in range(HISTORY_CRAWL_PAGES):
        if not oldest:
            break
        try:
            page_body = client.check(
                f"https://t.me/s/{handle}?before={oldest}", fetch_title=True).body_text
            page_posts = extract_channel_posts(page_body)
        except Exception:  # noqa: BLE001 — pagination is best-effort
            break
        fresh = 0
        for post in page_posts:
            if post["text"] and post["id"] and post["id"] not in seen_ids:
                seen_ids.add(str(post["id"]))
                history.append({
                    "id": post["id"], "date": post["date"],
                    "views": post["views"],
                    "text": clean_html_fragment(str(post["text"]))[:160],
                })
                fresh += 1
        new_oldest = min((int(p["num"]) for p in page_posts), default=0)
        if not new_oldest or new_oldest >= oldest:
            break
        oldest = new_oldest
        if fresh == 0:
            break
    return history


def scan_telegram_channel(handle: str, client: HttpClient, *, target: str) -> tuple[Finding, ...]:
    """Full public-channel scan: header, recent posts and bounded history."""
    body = client.check(f"https://t.me/s/{handle}", fetch_title=True).body_text
    header = parse_channel_page(body)
    if header is None:
        result = client.check(f"https://t.me/{handle}", fetch_title=True)
        status = "candidate" if result.status_code and result.status_code < 400 else "unknown"
        if status != "candidate":
            return (
                Finding(
                    module="telegram-baseline", source="telegram-url", target=target,
                    status=status, url=result.final_url or f"https://t.me/{handle}",
                    title=result.title, http_status=result.status_code,
                    confidence="low",
                    evidence=result.error or f"HTTP {result.status_code}",
                    metadata={"target_type": "handle"},
                ),
            )
        return (
            Finding(
                module="telegram-baseline", source="telegram-profile", target=target,
                status="candidate", url=f"https://t.me/{handle}",
                title=result.title or handle, http_status=result.status_code,
                confidence="medium",
                evidence=f"Telegram user alias '{handle}' exists",
                metadata={"target_type": "handle"},
            ),
        )

    title = header["title"] or handle
    subscribers = header["subscribers"]
    findings: list[Finding] = [
        Finding(
            module="telegram-baseline", source="telegram-channel", target=target,
            status="candidate", url=f"https://t.me/s/{handle}",
            title=f"Channel '{title}' — {subscribers}",
            confidence="high",
            evidence=f"Public channel preview at t.me/s/{handle}",
            metadata={
                "target_type": "channel",
                "channel_title": str(title),
                "subscribers": str(subscribers),
                "description": str(header["description"]),
            },
        ),
    ]

    posts = extract_channel_posts(body)
    for index, post in enumerate(posts[-RECENT_POSTS_SHOWN:]):
        text = clean_html_fragment(str(post["text"]))
        if not text:
            continue
        metadata = {"recency": f"last-{index + 1}", "target_type": "post"}
        if post["date"]:
            metadata["date"] = str(post["date"])
        if post["views"]:
            metadata["views"] = str(post["views"])
        findings.append(Finding(
            module="telegram-baseline", source="telegram-post", target=target,
            status="candidate", url=f"https://t.me/{handle}/{post['num']}",
            title=text[:280], confidence="high",
            evidence=f"Recent post {post['id']}", metadata=metadata,
        ))

    history = crawl_channel_history(handle, client, posts)
    if history:
        findings.append(Finding(
            module="telegram-baseline", source="telegram-history", target=target,
            status="candidate", url=f"https://t.me/s/{handle}",
            title=(f"Public history crawled: {len(history)} messages "
                   f"(avg views: {average_views([h['views'] for h in history])})"),
            confidence="high",
            evidence=f"Bounded history crawl of t.me/s/{handle}",
            metadata={
                "target_type": "history",
                "message_count": str(len(history)),
                # first N messages serialized compactly; full list stays in reports via extra
                "messages_preview": " | ".join(str(h["text"])[:60] for h in history[:10]),
            },
        ))
    return tuple(findings)
