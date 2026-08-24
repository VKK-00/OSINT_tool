"""Public person-source enrichment modules.

All sources are public APIs used without login sessions:
- GitHub REST users endpoint (self-published account metadata);
- Mastodon accounts/lookup on the account's own instance;
- Bluesky public AppView getProfile;
- Wikidata entity search for public-figure person disambiguation.

These modules surface only what a person or platform publishes publicly.
They do not log into anything and do not enumerate private data.
"""
from __future__ import annotations

import html as html_mod
import json
import re
from dataclasses import dataclass
from urllib.parse import quote

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient

GITHUB_API = "https://api.github.com/users/{username}"


def _json_object(result) -> dict | None:
    try:
        payload = json.loads(result.body_text)
    except (json.JSONDecodeError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _json_value(result):
    """Parsed JSON of any shape (dict or list); None on parse failure."""
    try:
        return json.loads(result.body_text)
    except (json.JSONDecodeError, TypeError):
        return None


def _strip_html(value: str, *, limit: int = 300) -> str:
    text = re.sub(r"<[^>]+>", " ", value or "")
    return re.sub(r"\s+", " ", html_mod.unescape(text)).strip()[:limit]


def _metadata(**values: object) -> dict[str, str]:
    data = {
        key: str(value).strip()
        for key, value in values.items()
        if value is not None and str(value).strip()
    }
    return data


@dataclass(frozen=True)
class GitHubUserModule:
    name: str = "github-user"
    supported_targets: tuple[str, ...] = ("username",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        username = target.value.strip().lstrip("@")
        if not username:
            return (
                Finding(
                    module=self.name, source="normalizer", target=target.value,
                    status="invalid", confidence="high",
                    evidence="Username is empty after normalization.",
                ),
            )
        url = GITHUB_API.format(username=quote(username))
        if not config.live:
            return (
                Finding(
                    module=self.name, source="github-api", target=target.value,
                    status="planned", url=url, confidence="not_checked",
                    evidence="Dry run only. Pass --live to fetch public GitHub account metadata.",
                    metadata={"github_username": username},
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        result = client.check(url, headers={"Accept": "application/vnd.github+json"})
        if result.status_code == 404:
            return (
                Finding(
                    module=self.name, source="github-api", target=target.value,
                    status="not_found", url=url, http_status=404,
                    confidence="high",
                    evidence=f"No public GitHub account '{username}'.",
                    metadata={"github_username": username},
                ),
            )
        if result.status_code != 200:
            return (
                Finding(
                    module=self.name, source="github-api", target=target.value,
                    status="unknown", url=url, http_status=result.status_code,
                    confidence="low",
                    evidence=result.error or f"HTTP {result.status_code} from GitHub API.",
                    metadata={"github_username": username},
                ),
            )
        payload = _json_object(result)
        if payload is None:
            return (
                Finding(
                    module=self.name, source="github-api", target=target.value,
                    status="error", url=url, http_status=result.status_code,
                    confidence="low",
                    evidence="GitHub API returned a non-JSON body.",
                ),
            )
        metadata = _metadata(
            github_username=payload.get("login", username),
            github_id=payload.get("id"),
            name=payload.get("name"),
            company=payload.get("company"),
            blog=payload.get("blog"),
            location=payload.get("location"),
            public_email=payload.get("email"),
            bio=_strip_html(str(payload.get("bio") or ""), limit=500),
            twitter_username=payload.get("twitter_username"),
            public_repos=payload.get("public_repos"),
            followers=payload.get("followers"),
            created_at=str(payload.get("created_at") or "")[:10] or None,
            profile_url=payload.get("html_url"),
        )
        confidence = "high" if (payload.get("name") or payload.get("email")) else "medium"
        return (
            Finding(
                module=self.name, source="github-api", target=target.value,
                status="candidate",
                url=payload.get("html_url") or url,
                title=str(payload.get("name") or payload.get("login") or username),
                http_status=200,
                confidence=confidence,
                evidence=f"Public GitHub account '{payload.get('login', username)}' exists.",
                metadata={"github_username": username, **metadata},
            ),
        )


@dataclass(frozen=True)
class MastodonLookupModule:
    name: str = "mastodon-lookup"
    supported_targets: tuple[str, ...] = ("username",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        parsed = normalize_mastodon_acct(target.value)
        if not parsed:
            return (
                Finding(
                    module=self.name, source="normalizer", target=target.value,
                    status="invalid", confidence="high",
                    evidence="Could not normalize input into a Mastodon @user or @user@instance handle.",
                ),
            )
        user, instance = parsed
        url = f"https://{instance}/api/v1/accounts/lookup?acct={quote(user + '@' + instance)}"
        if not config.live:
            return (
                Finding(
                    module=self.name, source="mastodon-lookup", target=target.value,
                    status="planned", url=url, confidence="not_checked",
                    evidence="Dry run only. Pass --live to query the public Mastodon lookup API.",
                    metadata={"mastodon_instance": instance},
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        result = client.check(url)
        if result.status_code == 404:
            return (
                Finding(
                    module=self.name, source="mastodon-lookup", target=target.value,
                    status="not_found", url=url, http_status=404,
                    confidence="high",
                    evidence=f"No Mastodon account '{user}@{instance}' on its own instance.",
                    metadata={"mastodon_instance": instance},
                ),
            )
        payload = _json_object(result) if result.status_code == 200 else None
        if payload is None or "id" not in payload:
            return (
                Finding(
                    module=self.name, source="mastodon-lookup", target=target.value,
                    status="unknown", url=url, http_status=result.status_code,
                    confidence="low",
                    evidence=result.error or f"HTTP {result.status_code} from Mastodon lookup.",
                    metadata={"mastodon_instance": instance},
                ),
            )
        metadata = _metadata(
            mastodon_account=f"@{payload.get('acct') or user}@{instance}",
            mastodon_instance=instance,
            account_id=payload.get("id"),
            display_name=payload.get("display_name"),
            note=_strip_html(str(payload.get("note") or "")),
            followers=payload.get("followers_count"),
            following=payload.get("following_count"),
            posts=payload.get("statuses_count"),
            created_at=str(payload.get("created_at") or "")[:10] or None,
            is_bot="yes" if payload.get("bot") else None,
            is_locked="yes" if payload.get("locked") else None,
        )
        findings: list[Finding] = [
            Finding(
                module=self.name, source="mastodon-lookup", target=target.value,
                status="candidate", url=str(payload.get("url") or url),
                title=str(payload.get("display_name") or f"@{payload.get('acct') or user}"),
                http_status=200, confidence="medium",
                evidence=f"Public Mastodon account @{payload.get('acct') or user}@{instance} exists.",
                metadata={"mastodon_instance": instance, **metadata},
            )
        ]
        posts_finding = _mastodon_recent_statuses(
            client, str(instance), str(payload.get("id") or ""), target.value,
            profile_url=str(payload.get("url") or f"https://{instance}/@{user}"),
        )
        if posts_finding is not None:
            findings.append(posts_finding)
        return tuple(findings)


def _mastodon_recent_statuses(
    client: HttpClient,
    instance: str,
    account_id: str,
    target: str,
    *,
    limit: int = 5,
    profile_url: str = "",
) -> Finding | None:
    """Recent public posts of the account via the same-instance public API."""
    if not account_id:
        return None
    url = f"https://{instance}/api/v1/accounts/{quote(account_id)}/statuses?limit={limit}"
    try:
        result = client.check(url)
        payload = _json_value(result) if getattr(result, "status_code", None) == 200 else None
    except Exception:  # noqa: BLE001 - post enrichment is best-effort
        return None
    if not isinstance(payload, list):
        return None
    rows = []
    for post in payload:
        if not isinstance(post, dict):
            continue
        text = _strip_html(str(post.get("content") or ""), limit=100)
        created = str(post.get("created_at") or "")[:10]
        rows.append(" | ".join(filter(None, (created, text))))
    metadata = {
        "fetched_post_count": str(len(rows)),
        "recent_posts": " || ".join(rows),
    }
    return Finding(
        module="mastodon-lookup", source="mastodon-posts", target=target,
        status="candidate", url=profile_url or url,
        http_status=result.status_code, confidence="low",
        title=f"Recent public posts: {len(rows)} fetched",
        evidence="Latest public statuses from the account's own instance API.",
        metadata=metadata,
    )


def normalize_mastodon_acct(value: str) -> tuple[str, str] | None:
    raw = value.strip().lstrip("@")
    if "://" in raw:
        parsed = raw.split("://", 1)[-1]
        host, _, path = parsed.partition("/")
        parts = tuple(part for part in path.split("/") if part)
        if not host or not parts:
            return None
        last = parts[-1].lstrip("@")
        user, _, domain = last.partition("@")
        return _acct_pair(user or "", domain or host)
    if "@" in raw:
        user, _, instance = raw.partition("@")
        return _acct_pair(user, instance)
    return _acct_pair(raw, "mastodon.social")


def _acct_pair(user: str, instance: str) -> tuple[str, str] | None:
    user = user.strip().lstrip("@")
    instance = instance.strip().lower()
    if not re.fullmatch(r"[A-Za-z0-9_]+", user):
        return None
    if not re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", instance):
        return None
    return user, instance


@dataclass(frozen=True)
class BlueskyProfileModule:
    name: str = "bluesky-profile"
    supported_targets: tuple[str, ...] = ("username",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        actor = target.value.strip().lstrip("@")
        if not (actor.startswith("did:") or "." in actor):
            return (
                Finding(
                    module=self.name, source="normalizer", target=target.value,
                    status="skipped", confidence="high",
                    evidence="Bluesky handles contain a dot (for example name.bsky.social); input skipped.",
                ),
            )
        url = (
            "https://api.bsky.app/xrpc/app.bsky.actor.getProfile?actor="
            + quote(actor, safe="")
        )
        if not config.live:
            return (
                Finding(
                    module=self.name, source="appview-api", target=target.value,
                    status="planned", url=url, confidence="not_checked",
                    evidence="Dry run only. Pass --live to query the public Bluesky AppView.",
                    metadata={"bluesky_handle": actor},
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        result = client.check(url)
        if result.status_code in {400, 404}:
            return (
                Finding(
                    module=self.name, source="appview-api", target=target.value,
                    status="not_found", url=url, http_status=result.status_code,
                    confidence="medium",
                    evidence=f"Bluesky AppView reports no account '{actor}'.",
                    metadata={"bluesky_handle": actor},
                ),
            )
        payload = _json_object(result) if result.status_code == 200 else None
        if payload is None or not payload.get("did"):
            return (
                Finding(
                    module=self.name, source="appview-api", target=target.value,
                    status="unknown", url=url, http_status=result.status_code,
                    confidence="low",
                    evidence=result.error or f"HTTP {result.status_code} from Bluesky AppView.",
                    metadata={"bluesky_handle": actor},
                ),
            )
        metadata = _metadata(
            bluesky_handle=payload.get("handle"),
            did=payload.get("did"),
            display_name=payload.get("displayName"),
            description=_strip_html(str(payload.get("description") or "")),
            followers=payload.get("followersCount"),
            following=payload.get("followsCount"),
            posts=payload.get("postsCount"),
            created_at=str(payload.get("createdAt") or "")[:10] or None,
        )
        findings: list[Finding] = [
            Finding(
                module=self.name, source="appview-api", target=target.value,
                status="candidate", url=f"https://bsky.app/profile/{payload.get('handle', actor)}",
                title=str(payload.get("displayName") or payload.get("handle") or actor),
                http_status=200, confidence="medium",
                evidence=f"Bluesky account '{payload.get('handle', actor)}' exists.",
                metadata={"bluesky_handle": str(payload.get("handle") or actor), **metadata},
            )
        ]
        feed_finding = _bluesky_recent_feed(client, actor, target.value)
        if feed_finding is not None:
            findings.append(feed_finding)
        return tuple(findings)


def _bluesky_recent_feed(
    client: HttpClient, actor: str, target: str, *, limit: int = 5
) -> Finding | None:
    """Recent public posts via the public AppView author feed (no auth)."""
    url = (
        "https://api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?limit="
        + str(limit)
        + "&actor="
        + quote(actor, safe="")
    )
    try:
        result = client.check(url)
        payload = _json_value(result) if getattr(result, "status_code", None) == 200 else None
    except Exception:  # noqa: BLE001 - feed enrichment is best-effort
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("feed"), list):
        return None
    rows = []
    for item in payload["feed"]:
        post = item.get("post") if isinstance(item, dict) else None
        record = post.get("record") if isinstance(post, dict) else None
        if not isinstance(record, dict):
            continue
        text = _strip_html(str(record.get("text") or ""), limit=100)
        created = str(record.get("createdAt") or "")[:10]
        rows.append(" | ".join(filter(None, (created, text))))
    if not rows:
        return None
    return Finding(
        module="bluesky-profile", source="bluesky-feed", target=target,
        status="candidate", url=f"https://bsky.app/profile/{actor}",
        http_status=result.status_code, confidence="low",
        title=f"Recent public posts: {len(rows)} fetched",
        evidence="Latest public posts from the Bluesky AppView author feed.",
        metadata={
            "fetched_post_count": str(len(rows)),
            "recent_posts": " || ".join(rows),
        },
    )


@dataclass(frozen=True)
class WikidataPersonModule:
    name: str = "wikidata-person"
    supported_targets: tuple[str, ...] = ("person",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        person = re.sub(r"\s+", " ", target.value.replace('"', "")).strip()
        if len(person) < 2:
            return (
                Finding(
                    module=self.name, source="normalizer", target=target.value,
                    status="invalid", confidence="high",
                    evidence="Person name is too short for Wikidata entity search.",
                ),
            )
        search_api = (
            "https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json&origin=*"
            "&type=item&language=en&limit=5&search=" + quote(person)
        )
        if not config.live:
            return (
                Finding(
                    module=self.name, source="wikidata-search", target=target.value,
                    status="planned", url=search_api, confidence="not_checked",
                    evidence="Dry run only. Pass --live to search public Wikidata entities.",
                    metadata={"person": person},
                ),
            )

        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        search_result = client.check(search_api)
        search_payload = _json_object(search_result) if search_result.status_code == 200 else None
        candidates = [
            item for item in (search_payload or {}).get("search", [])
            if isinstance(item, dict) and item.get("id")
        ]
        if not candidates:
            return (
                Finding(
                    module=self.name, source="wikidata-search", target=target.value,
                    status="not_found", url=search_api, http_status=search_result.status_code,
                    confidence="low",
                    evidence=f"No Wikidata entity matched the name '{person}'.",
                    metadata={"person": person},
                ),
            )
        ids = ",".join(str(item["id"]) for item in candidates[:5])
        entities_url = (
            "https://www.wikidata.org/w/api.php?action=wbgetentities&format=json&origin=*"
            "&props=labels|descriptions|aliases|claims&languages=en&ids=" + quote(ids)
        )
        entities_result = client.check(entities_url)
        entities_payload = _json_object(entities_result) if entities_result.status_code == 200 else {}
        humans = extract_wikidata_humans(entities_payload)
        if not humans:
            return (
                Finding(
                    module=self.name, source="wikidata-search", target=target.value,
                    status="not_found", url=entities_url, http_status=entities_result.status_code,
                    confidence="low",
                    evidence=f"Wikidata matches for '{person}' are not human entities.",
                    metadata={
                        "person": person,
                        "search_hits": str(len(candidates)),
                    },
                ),
            )
        findings: list[Finding] = []
        for entity in humans[:3]:
            findings.append(
                Finding(
                    module=self.name, source="wikidata-entity", target=target.value,
                    status="candidate",
                    url=f"https://www.wikidata.org/wiki/{entity['wikidata_id']}",
                    title=str(entity.get("label") or entity["wikidata_id"]),
                    http_status=entities_result.status_code,
                    confidence="low",
                    evidence=(
                        "Name-match only: confirm identity before attributing anything "
                        "to a specific person."
                    ),
                    metadata={
                        "person": person,
                        "search_hits": str(len(candidates)),
                        **entity,
                    },
                ),
            )
        return tuple(findings)


def extract_wikidata_humans(payload: dict) -> tuple[dict[str, str], ...]:
    """Filter wbgetentities output down to human (P31=Q5) entities."""
    if not isinstance(payload, dict):
        return ()
    entities = payload.get("entities")
    if not isinstance(entities, dict):
        return ()
    humans: list[dict[str, str]] = []
    for entity_id, entity in entities.items():
        if not isinstance(entity, dict):
            continue
        claims = entity.get("claims")
        if not isinstance(claims, dict):
            claims = {}
        instance_claims = claims.get("P31") if isinstance(claims.get("P31"), list) else []
        is_human = False
        for claim in instance_claims:
            try:
                value = claim["mainsnak"]["datavalue"]["value"]
            except (KeyError, TypeError, AttributeError):
                continue
            if isinstance(value, dict) and value.get("id") == "Q5":
                is_human = True
                break
        if not is_human:
            continue

        current_entity = entity

        def _lang_text(section: str, *, entity=current_entity) -> str:
            node = entity.get(section)
            entry = node.get("en") if isinstance(node, dict) else None
            if not isinstance(entry, dict):
                return ""
            return str(entry.get("value") or "")

        alias_node = entity.get("aliases")
        lang_aliases = alias_node.get("en") if isinstance(alias_node, dict) else None
        if isinstance(lang_aliases, list):
            alias_entries = lang_aliases
        elif isinstance(lang_aliases, dict) and isinstance(lang_aliases.get("value"), list):
            alias_entries = lang_aliases["value"]
        else:
            alias_entries = []
        aliases = ", ".join(sorted({
            str(alias.get("value") or "") for alias in alias_entries if isinstance(alias, dict)
        }))[:200]
        born = _claim_year(claims, "P569")
        died = _claim_year(claims, "P570")
        humans.append(_metadata(
            wikidata_id=entity_id,
            label=_lang_text("labels"),
            description=_lang_text("descriptions"),
            aliases=aliases or None,
            born=born,
            died=died,
        ))
    return tuple(humans)


def _claim_year(claims: dict, property_id: str) -> str | None:
    property_claims = claims.get(property_id)
    if not isinstance(property_claims, list):
        return None
    for claim in property_claims:
        try:
            time_value = claim["mainsnak"]["datavalue"]["value"]
        except (KeyError, TypeError, AttributeError):
            continue
        if isinstance(time_value, dict) and time_value.get("time"):
            return str(time_value["time"])[:5].lstrip("+")
    return None

@dataclass(frozen=True)
class GithubCommitEmailsModule:
    """Author emails from recent public commits of a GitHub user.

    Commit authorship emails are self-published by the committer inside
    their own commits (git config), fetched through the keyless GitHub REST
    API. Bounded to a handful of recently-pushed repos to respect rate limits.
    """

    name: str = "github-commit-emails"
    supported_targets: tuple[str, ...] = ("username",)

    MAX_REPOS = 3
    MAX_COMMITS_PER_REPO = 30

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        username = target.value.strip().lstrip("@")
        if not username:
            return (
                Finding(
                    module=self.name, source="normalizer", target=target.value,
                    status="invalid", confidence="high",
                    evidence="Username is empty after normalization.",
                ),
            )
        repos_url = (
            "https://api.github.com/users/" + quote(username) +
            "/repos?sort=pushed&direction=desc&per_page=" + str(self.MAX_REPOS)
        )
        if not config.live:
            return (
                Finding(
                    module=self.name, source="commit-emails", target=target.value,
                    status="planned", url=repos_url, confidence="not_checked",
                    evidence=(
                        "Dry run only. Pass --live to scan recent public commits "
                        "for self-published author emails."
                    ),
                    metadata={"github_username": username},
                ),
            )

        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        headers = {"Accept": "application/vnd.github+json"}

        account_result = client.check(
            f"https://api.github.com/users/{quote(username)}", headers=headers)
        if account_result.status_code == 404:
            return (
                Finding(
                    module=self.name, source="commit-emails", target=target.value,
                    status="not_found", confidence="high",
                    evidence=f"No public GitHub account '{username}'.",
                    metadata={"github_username": username},
                ),
            )
        account_payload = _json_object(account_result) if account_result.status_code == 200 else None
        if not isinstance(account_payload, dict):
            return (
                Finding(
                    module=self.name, source="commit-emails", target=target.value,
                    status="unknown", confidence="low",
                    evidence=account_result.error or f"HTTP {account_result.status_code} from GitHub.",
                    metadata={"github_username": username},
                ),
            )
        login = str(account_payload.get("login") or username)

        repos_result = client.check(repos_url, headers=headers)
        repos_payload = _json_value(repos_result) if repos_result.status_code == 200 else []
        repo_names: list[str] = []
        for repo in (repos_payload or []):
            if isinstance(repo, dict) and not repo.get("fork") and repo.get("name"):
                repo_names.append(str(repo["name"]))
        repo_names = repo_names[: self.MAX_REPOS]

        emails: dict[str, set[str]] = {}
        commit_total = 0
        for repo in repo_names:
            commits_url = (
                f"https://api.github.com/repos/{quote(login)}/{quote(repo)}"
                f"/commits?per_page={self.MAX_COMMITS_PER_REPO}"
            )
            commits_result = client.check(commits_url, headers=headers)
            commits = _json_value(commits_result) if commits_result.status_code == 200 else []
            if not isinstance(commits, list):
                continue
            for entry in commits:
                if not isinstance(entry, dict):
                    continue
                commit_total += 1
                git_author = (entry.get("commit") or {}).get("author") or {}
                email_addr = str(git_author.get("email") or "").strip().lower()
                name = str(git_author.get("name") or "").strip()
                if not email_addr or "noreply.github.com" in email_addr:
                    continue
                emails.setdefault(email_addr, set()).add(name or login)

        metadata = {
            "github_username": login,
            "repos_scanned": ", ".join(repo_names) or "-",
            "commits_reviewed": str(commit_total),
        }
        if not emails:
            metadata["note"] = (
                "No author emails in the most recent public commits "
                "(common for web-interface edits and privacy-set configs)."
            )
            return (
                Finding(
                    module=self.name, source="commit-emails", target=target.value,
                    status="not_found", confidence="low",
                    evidence=f"No commit-author emails found for '{login}' in recent pushes.",
                    metadata=metadata,
                ),
            )
        metadata["emails"] = ", ".join(sorted(emails))[:400]
        names = sorted({n for group in emails.values() for n in group})
        if names:
            metadata["author_names"] = ", ".join(names)[:200]
        return (
            Finding(
                module=self.name, source="commit-emails", target=target.value,
                status="candidate",
                url=f"https://github.com/{login}",
                title=f"Commit emails: {', '.join(sorted(emails)[:3])}",
                confidence="high" if len(emails) == 1 else "medium",
                evidence=(
                    "Self-published git author identity from public commit history "
                    "(recently pushed non-fork repositories)."
                ),
                metadata=metadata,
            ),
        )
