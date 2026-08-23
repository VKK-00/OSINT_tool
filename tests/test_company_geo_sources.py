"""Offline tests for Overpass geo verification, Mastodon/Bluesky feeds and GLEIF."""
from __future__ import annotations

import json
from unittest.mock import patch

from osint_toolkit.engine import RunConfig, ScanTarget
from osint_toolkit.http_client import HttpResult
from osint_toolkit.modules.company_intel import (
    GleifCompanyModule,
    parse_gleif_entities,
)
from osint_toolkit.modules.exif_photo import overpass_nearby_features
from osint_toolkit.modules.person_sources import BlueskyProfileModule, MastodonLookupModule


class FakeClient:
    def __init__(self, *results):
        self.results = list(results)

    def check(self, url, **kwargs):
        return self.results.pop(0)


def _json_result(url: str, payload) -> HttpResult:
    return HttpResult(
        url=url, final_url=url, status_code=200,
        body_text=json.dumps(payload), content_type="application/json",
    )


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def test_overpass_nearby_features_extracts_named_osm_objects(monkeypatch):
    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["url"] = url
        captured["params"] = params
        return FakeResponse({
            "elements": [
                {"type": "way", "tags": {"name": "Khreshchatyk St", "highway": "primary"}},
                {"type": "way", "tags": {"name": "Maidan Nezalezhnosti", "place": "square"}},
                {"type": "node", "tags": {"amenity": "cafe"}},  # unnamed -> skipped
            ]
        })

    monkeypatch.setattr("osint_toolkit.modules.exif_photo.httpx.get", fake_get)
    result = overpass_nearby_features(50.4501, 30.5234)
    assert "around:120,50.4501,30.5234" in captured["params"]["data"]
    assert result["nearby_feature_count"] == "3"
    assert "primary: Khreshchatyk St" in result["named_features"]
    assert "square: Maidan Nezalezhnosti" in result["named_features"]
    assert "cafe" not in result["named_features"].split("named")[0]


def _mastodon_flow(extra_statuses):
    lookup_payload = {
        "id": "77", "acct": "gargron", "display_name": "Eugen",
        "url": "https://mastodon.social/@gargron", "followers_count": 1,
    }
    results = [_json_result("lookup", lookup_payload)]
    if extra_statuses is not None:
        results.append(_json_result("statuses", extra_statuses))
    client = FakeClient(*results)
    with patch("osint_toolkit.modules.person_sources.HttpClient", return_value=client):
        findings = MastodonLookupModule().scan(ScanTarget("username", "gargron"), RunConfig(live=True))
    return findings


def test_mastodon_live_includes_recent_public_posts():
    statuses = [
        {"content": "<p>Hello world</p>", "created_at": "2026-06-01T10:00:00Z"},
        {"content": "<p>Second post</p>", "created_at": "2026-05-30T08:00:00Z"},
    ]
    findings = _mastodon_flow(statuses)
    sources = {f.source for f in findings}
    assert {"mastodon-lookup", "mastodon-posts"} <= sources
    posts = next(f for f in findings if f.source == "mastodon-posts")
    assert posts.metadata["fetched_post_count"] == "2"
    assert "Hello world" in posts.metadata["recent_posts"]
    assert "<p>" not in posts.metadata["recent_posts"]


def test_mastodon_without_statuses_still_returns_profile():
    findings = _mastodon_flow(None)
    assert len(findings) == 1
    assert findings[0].source == "mastodon-lookup"


def test_bluesky_live_includes_author_feed():
    profile_payload = {
        "did": "did:plc:x", "handle": "user.bsky.social",
        "displayName": "User", "followersCount": 3,
    }
    feed_payload = {
        "feed": [
            {"post": {"record": {"text": "First skeet", "createdAt": "2026-06-02T00:00:00Z"}}},
            {"post": {"record": {"text": "Second", "createdAt": "2026-06-01T00:00:00Z"}}},
        ]
    }
    client = FakeClient(
        _json_result("profile", profile_payload),
        _json_result("feed", feed_payload),
    )
    with patch("osint_toolkit.modules.person_sources.HttpClient", return_value=client):
        findings = BlueskyProfileModule().scan(
            ScanTarget("username", "user.bsky.social"), RunConfig(live=True))
    sources = {f.source for f in findings}
    assert {"appview-api", "bluesky-feed"} <= sources
    feed = next(f for f in findings if f.source == "bluesky-feed")
    assert "First skeet" in feed.metadata["recent_posts"]


def test_gleif_parses_entity_records():
    payload = {
        "data": [
            {
                "attributes": {
                    "lei": "5493001KJTIIGC8Y1R12",
                    "entity": {
                        "legalName": {"name": "Example Holdings PLC"},
                        "status": "ACTIVE",
                        "legalForm": {"name": "Public Limited Company"},
                        "registration": {"initialRegistrationDate": "2014-04-01T00:00:00Z"},
                    },
                    "legalAddress": {"country": "GB", "city": "London"},
                }
            }
        ]
    }
    entities = parse_gleif_entities(payload)
    assert len(entities) == 1
    entity = entities[0]
    assert entity["lei"] == "5493001KJTIIGC8Y1R12"
    assert entity["legal_name"] == "Example Holdings PLC"
    assert entity["country"] == "GB"
    assert entity["registered_at"] == "2014-04-01"


def test_gleif_dry_run_planned_and_lei_url():
    findings = GleifCompanyModule().scan(
        ScanTarget("company", "5493001KJTIIGC8Y1R12"), RunConfig())
    assert findings[0].status == "planned"


def test_gleif_live_search_by_name():
    module = GleifCompanyModule()
    client = FakeClient(_json_result("gleif", {
        "data": [{
            "attributes": {
                "lei": "12345678901234567890",
                "entity": {"legalName": {"name": "Test Company Ltd"}, "status": "ACTIVE"},
                "legalAddress": {"country": "UA", "city": "Kyiv"},
            }
        }]
    }))
    with patch("osint_toolkit.modules.company_intel._client", return_value=client):
        findings = module.scan(ScanTarget("company", "Test Company"), RunConfig(live=True))
    assert findings[0].status == "candidate"
    assert findings[0].metadata["legal_name"] == "Test Company Ltd"
    assert findings[0].metadata["country"] == "UA"


def test_company_kind_is_registered_target():
    from osint_toolkit.runtime import build_default_engine
    from osint_toolkit.search import TARGET_KINDS, find_search_profile

    assert "company" in TARGET_KINDS
    engine = build_default_engine()
    assert any(m.supported_targets == ("company",) for m in engine.modules)
    profile = find_search_profile("company-safe")
    assert profile is not None
