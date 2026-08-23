"""Offline tests for the osintkit -> osint_toolkit bridge layer."""
from __future__ import annotations

import asyncio

from osint_toolkit.engine import Finding
from osintkit.bridge import classify_target, core_confidence, engine_to_core


def test_transliterate_single_implementation():
    from osint_toolkit.translit import transliterate as unified
    from osintkit.core import transliterate as legacy

    assert legacy("ivanov") == unified("ivanov")
    out = legacy("ivanov")
    assert "ivanov" in out
    assert any("іван" in v for v in out)


def test_curated_username_subset_resolves_from_unified_db():
    from osintkit.modules.username import CURATED_TEMPLATES, curated_sites

    sites = curated_sites()
    assert len(sites) == len(CURATED_TEMPLATES)
    templates = {site.url_template for site in sites}
    assert templates == set(CURATED_TEMPLATES)


def test_classify_target():
    assert classify_target("a@b.com") == "email"
    assert classify_target("+380501234567") == "phone"
    assert classify_target("https://example.com") == "url"
    assert classify_target("ivanov1990") == "username"


def test_dorks_bridge_generates_dorks_and_telegram_lead():
    import urllib.parse

    from osintkit.modules.dorks import DorksModule

    findings = asyncio.run(DorksModule().run("ivan_petrov", None))
    kinds = {f.kind for f in findings}
    assert {"dork", "lead"} <= kinds
    assert any(f.kind == "lead" and f.value.startswith("Pivot: Telegram alias") for f in findings)
    assert any(
        "site:vk.com" in urllib.parse.unquote(f.extra.get("yandex", ""))
        for f in findings if f.kind == "dork"
    )


def test_engine_to_core_maps_confidence_and_extra():
    finding = Finding(
        module="dorks", source="dork", target="x", status="candidate",
        url="https://example.com", title="Label", confidence="unknown",
        metadata={"yandex": "https://yandex.com/search/?text=x"},
    )
    kind, extra = engine_to_core(finding)
    assert kind == "dork"
    assert extra["title"] == "Label"
    assert extra["status"] == "candidate"
    assert core_confidence(finding) == "low"


def test_telegram_channel_page_parsing():
    from osint_toolkit.modules.telegram import extract_channel_posts, parse_channel_page

    body = (
        '<span dir="auto">Test Channel</span>'
        '<div class="tgme_page_extra">1 234 subscribers</div>'
        '<div class="tgme_widget_message" data-post="testchannel/12">'
        '<time datetime="2026-01-02T10:00:00+00:00"></time>'
        '<div class="tgme_widget_message_views">1.2K</div>'
        '<div class="tgme_widget_message_text">Hello <b>world</b></div></div>'
    )
    header = parse_channel_page(body)
    assert header is not None
    assert header["title"] == "Test Channel"
    assert header["subscribers"] == "1 234 subscribers"
    posts = extract_channel_posts(body)
    assert len(posts) == 1
    assert posts[0]["num"] == 12
    assert posts[0]["views"] == "1.2K"


def test_parse_channel_page_rejects_non_channel():
    from osint_toolkit.modules.telegram import parse_channel_page

    assert parse_channel_page("<html>nothing here</html>") is None
