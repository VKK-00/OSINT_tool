"""Offline tests for public person-source enrichment modules."""
from __future__ import annotations

import json
from unittest.mock import patch

from osint_toolkit.engine import RunConfig, ScanTarget
from osint_toolkit.http_client import HttpResult
from osint_toolkit.modules.person_sources import (
    BlueskyProfileModule,
    GitHubUserModule,
    MastodonLookupModule,
    WikidataPersonModule,
    extract_wikidata_humans,
    normalize_mastodon_acct,
)


class FakeClient:
    def __init__(self, *results: HttpResult):
        self.results = list(results)
        self.requests: list[str] = []

    def check(self, url, **kwargs):
        self.requests.append(url)
        return self.results.pop(0)


def _json_result(url: str, payload) -> HttpResult:
    return HttpResult(
        url=url,
        final_url=url,
        status_code=200,
        body_text=json.dumps(payload),
        content_type="application/json",
    )


def test_github_user_dry_run_planned():
    findings = GitHubUserModule().scan(ScanTarget("username", "@durov"), RunConfig())
    assert len(findings) == 1
    assert findings[0].status == "planned"
    assert "api.github.com/users/durov" in findings[0].url


def test_github_user_live_404_not_found():
    module = GitHubUserModule()
    client = FakeClient(HttpResult(url="x", final_url="x", status_code=404))
    with patch("osint_toolkit.modules.person_sources.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("username", "ghost_user"), RunConfig(live=True))
    assert findings[0].status == "not_found"
    assert findings[0].confidence == "high"


def test_github_user_live_parses_public_metadata():
    payload = {
        "login": "durov",
        "id": 1,
        "name": "Pavel D.",
        "company": "@telegram",
        "location": "Dubai",
        "email": "pavel@example.com",
        "bio": "Founder of Telegram",
        "twitter_username": "durov",
        "public_repos": 5,
        "followers": 42,
        "created_at": "2008-01-07T00:00:00Z",
        "html_url": "https://github.com/durov",
    }
    module = GitHubUserModule()
    client = FakeClient(_json_result("https://api.github.com/users/durov", payload))
    with patch("osint_toolkit.modules.person_sources.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("username", "durov"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "candidate"
    assert finding.confidence == "high"  # name+email present
    assert finding.metadata["location"] == "Dubai"
    assert finding.metadata["public_email"] == "pavel@example.com"
    assert finding.metadata["created_at"] == "2008-01-07"


def test_mastodon_normalizer_and_lookup():
    assert normalize_mastodon_acct("gargron") == ("gargron", "mastodon.social")
    assert normalize_mastodon_acct("@user@fosstodon.org") == ("user", "fosstodon.org")
    assert normalize_mastodon_acct("https://fosstodon.org/@user") == ("user", "fosstodon.org")
    assert normalize_mastodon_acct("bad handle!") is None

    payload = {
        "id": "1",
        "acct": "gargron",
        "display_name": "Eugen",
        "note": "<p>Founder of Mastodon</p>",
        "followers_count": 123,
        "statuses_count": 9,
        "created_at": "2016-01-01T00:00:00Z",
        "url": "https://mastodon.social/@gargron",
        "bot": False,
    }
    module = MastodonLookupModule()
    client = FakeClient(
        _json_result("https://mastodon.social/api/v1/accounts/lookup?acct=gargron%40mastodon.social", payload)
    )
    with patch("osint_toolkit.modules.person_sources.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("username", "gargron"), RunConfig(live=True))
    assert findings[0].status == "candidate"
    assert findings[0].metadata["display_name"] == "Eugen"
    assert findings[0].metadata["note"] == "Founder of Mastodon"
    assert findings[0].metadata["mastodon_instance"] == "mastodon.social"

    missing = FakeClient(HttpResult(url="x", final_url="x", status_code=404))
    with patch("osint_toolkit.modules.person_sources.HttpClient", return_value=missing):
        findings = MastodonLookupModule().scan(ScanTarget("username", "nobody"), RunConfig(live=True))
    assert findings[0].status == "not_found"


def test_bluesky_requires_dotted_handle():
    skipped = BlueskyProfileModule().scan(ScanTarget("username", "plainname"), RunConfig(live=True))
    assert skipped[0].status == "skipped"


def test_bluesky_live_parses_profile():
    payload = {
        "did": "did:plc:abc",
        "handle": "testuser.bsky.social",
        "displayName": "Test User",
        "description": "OSINT researcher",
        "followersCount": 10,
        "postsCount": 3,
        "createdAt": "2023-04-01T00:00:00Z",
    }
    module = BlueskyProfileModule()
    client = FakeClient(_json_result("https://api.bsky.app/xrpc/app.bsky.actor.getProfile", payload))
    with patch("osint_toolkit.modules.person_sources.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("username", "testuser.bsky.social"), RunConfig(live=True))
    assert findings[0].status == "candidate"
    assert findings[0].metadata["bluesky_handle"] == "testuser.bsky.social"
    assert findings[0].metadata["description"] == "OSINT researcher"

    invalid = FakeClient(HttpResult(url="x", final_url="x", status_code=400))
    with patch("osint_toolkit.modules.person_sources.HttpClient", return_value=invalid):
        findings = BlueskyProfileModule().scan(ScanTarget("username", "gone.example.com"), RunConfig(live=True))
    assert findings[0].status == "not_found"


def test_wikidata_extracts_only_humans_with_birth_year():
    entities_payload = {
        "entities": {
            "Q123": {
                "labels": {"en": {"value": "John Smith"}},
                "descriptions": {"en": {"value": "fictional character"}},
                "claims": {"P31": [{"mainsnak": {"datavalue": {"value": {"id": "Q5"}}}}]},
            },
            "Q456": {
                "labels": {"en": {"value": "Jane Doe"}},
                "descriptions": {"en": {"value": "researcher"}},
                "aliases": {"en": [{"value": "J. Doe"}]},
                "claims": {
                    "P31": [{"mainsnak": {"datavalue": {"value": {"id": "Q5"}}}}],
                    "P569": [{"mainsnak": {"datavalue": {"value": {"time": "+1980-03-15T00:00:00Z"}}}}],
                },
            },
            "Q789": {
                "labels": {"en": {"value": "Some Company"}},
                "claims": {"P31": [{"mainsnak": {"datavalue": {"value": {"id": "Q4830453"}}}}]},
            },
        }
    }
    humans = extract_wikidata_humans(entities_payload)
    ids = {h["wikidata_id"] for h in humans}
    assert ids == {"Q123", "Q456"}
    jane = next(h for h in humans if h["wikidata_id"] == "Q456")
    assert jane["born"] == "1980"
    assert jane["aliases"] == "J. Doe"


def test_wikidata_module_two_step_flow():
    search_payload = {
        "search": [
            {"id": "Q456", "label": "Jane Doe", "description": "researcher"},
            {"id": "Q789", "label": "Doe Corp"},
        ]
    }

    def fake_check(url, **kwargs):
        if "wbsearchentities" in url:
            return _json_result(url, search_payload)
        return _json_result(
            url,
            {
                "entities": {
                    "Q456": {
                        "labels": {"en": {"value": "Jane Doe"}},
                        "descriptions": {"en": {"value": "researcher"}},
                        "claims": {"P31": [{"mainsnak": {"datavalue": {"value": {"id": "Q5"}}}}]},
                    },
                    "Q789": {},
                }
            },
        )

    client = FakeClient()
    client.check = fake_check  # type: ignore[method-assign]
    with patch("osint_toolkit.modules.person_sources.HttpClient", return_value=client):
        findings = WikidataPersonModule().scan(ScanTarget("person", "Jane Doe"), RunConfig(live=True))
    assert len(findings) == 1
    assert findings[0].status == "candidate"
    assert findings[0].metadata["wikidata_id"] == "Q456"
    assert findings[0].confidence == "low"  # name-match only


def test_wikidata_dry_run_planned():
    findings = WikidataPersonModule().scan(ScanTarget("person", "Ivan Petrenko"), RunConfig())
    assert findings[0].status == "planned"
