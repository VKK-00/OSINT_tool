"""Tests for GitHub commit-email enrichment (gitrecon-style, keyless)."""
from __future__ import annotations

import json
from unittest.mock import patch

from osint_toolkit.engine import RunConfig, ScanTarget
from osint_toolkit.http_client import HttpResult
from osint_toolkit.modules.person_sources import GithubCommitEmailsModule


class FakeClient:
    def __init__(self, routes: dict[str, object]):
        self.routes = routes

    def check(self, url, **kwargs):
        for pattern, payload in self.routes.items():
            if pattern in url:
                return HttpResult(url=url, final_url=url, status_code=200,
                                  body_text=json.dumps(payload),
                                  content_type="application/json")
        return HttpResult(url=url, final_url=url, status_code=404)


def test_commit_emails_dry_run_planned():
    findings = GithubCommitEmailsModule().scan(
        ScanTarget("username", "durov"), RunConfig())
    assert findings[0].status == "planned"


def test_commit_emails_extracts_real_author_emails():
    routes = {
        "/users/durov/repos": [
            {"name": "proj-a", "fork": False},
            {"name": "proj-b", "fork": True},   # fork skipped
            {"name": "proj-c", "fork": False},
        ],
        "/users/durov": {"login": "durov", "id": 1},  # must come after /repos
        "repos/durov/proj-a/commits": [
            {"commit": {"author": {"name": "Pavel", "email":
             "pavel@real-mail.example"}}},
            {"commit": {"author": {"name": "Pavel", "email":
             "pavel@users.noreply.github.com"}}},  # noreply filtered
        ],
        "repos/durov/proj-b/commits": [],
        "repos/durov/proj-c/commits": [
            {"commit": {"author": {"name": "Pavel", "email":
             "pavel@other.example"}}},
        ],
    }
    module = GithubCommitEmailsModule()
    with patch("osint_toolkit.modules.person_sources.HttpClient",
               return_value=FakeClient(routes)):
        findings = module.scan(ScanTarget("username", "durov"), RunConfig(live=True))
    finding = findings[0]
    assert finding.status == "candidate"
    emails = {e.strip() for e in finding.metadata["emails"].split(",")}
    assert emails == {"pavel@real-mail.example", "pavel@other.example"}
    # two distinct addresses -> medium; a single one would be 'high'
    assert finding.confidence == "medium"
    # the noreply commit is *reviewed* but its address is filtered out
    assert finding.metadata["commits_reviewed"] == "3"
    assert finding.metadata["repos_scanned"] == "proj-a, proj-c"
    assert "noreply" not in finding.metadata["emails"]


def test_commit_emails_account_missing_not_found():
    module = GithubCommitEmailsModule()
    client = FakeClient({})  # everything 404
    with patch("osint_toolkit.modules.person_sources.HttpClient", return_value=client):
        findings = module.scan(ScanTarget("username", "ghost"), RunConfig(live=True))
    assert findings[0].status == "not_found"


def test_commit_emails_no_emails_in_commits():
    routes = {
        "/users/clean?": {"login": "clean"},
        "/users/clean/repos": [{"name": "repo1", "fork": False}],
        "repos/clean/repo1/commits": [
            {"commit": {"author": {"name": "C", "email":
             "c@users.noreply.github.com"}}},
        ],
    }
    module = GithubCommitEmailsModule()
    with patch("osint_toolkit.modules.person_sources.HttpClient",
               return_value=FakeClient(routes)):
        findings = module.scan(ScanTarget("username", "clean"), RunConfig(live=True))
    assert findings[0].status == "not_found"
