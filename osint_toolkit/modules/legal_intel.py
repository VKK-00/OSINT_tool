"""Legal intelligence: CourtListener search (free API key, Token auth)."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import quote

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient

CL_SEARCH_URL = "https://www.courtlistener.com/api/rest/v4/search/"
CL_PROFILE_BASE = "https://www.courtlistener.com"


def _clean(value, *, limit: int | None = None) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit] if limit else text


@dataclass(frozen=True)
class CourtListenerModule:
    """US court-document search over opinions + RECAP filings.

    Free API key required (register at courtlistener.com); covers the
    legal-database direction started by the RECAP source-pack entry.
    """

    name: str = "courtlistener-search"
    supported_targets: tuple[str, ...] = ("company", "person")

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        query = _clean(target.value.replace('"', ""))
        api_key = os.environ.get("COURTLISTENER_API_KEY", "").strip()
        url = f"{CL_SEARCH_URL}?q={quote(query)}&type=r&order_by=score%20desc"
        if len(query) < 3:
            return (
                Finding(
                    module=self.name, source="normalizer", target=target.value,
                    status="invalid", confidence="high",
                    evidence="Query too short for a meaningful court-document search.",
                ),
            )
        if not api_key:
            return (
                Finding(
                    module=self.name, source="cl-api", target=target.value,
                    status="skipped", confidence="high",
                    evidence=(
                        "COURTLISTENER_API_KEY is not set; register free at "
                        "https://www.courtlistener.com/profile/sign-up/ to enable "
                        "court-document search."
                    ),
                ),
            )
        if not config.live:
            return (
                Finding(
                    module=self.name, source="cl-api", target=target.value,
                    status="planned", url=url, confidence="not_checked",
                    evidence="Dry run only. Pass --live to search RECAP/opinions.",
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        result = client.check(url, headers={"Authorization": f"Token {api_key}"})
        payload = _json_dict(result) if result.status_code == 200 else None
        results = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(results, list):
            return (
                Finding(
                    module=self.name, source="cl-api", target=target.value,
                    status="unknown", http_status=result.status_code,
                    confidence="low",
                    evidence=result.error or f"HTTP {result.status_code} from CourtListener.",
                ),
            )
        rows = [item for item in results if isinstance(item, dict)]
        if not rows:
            return (
                Finding(
                    module=self.name, source="cl-api", target=target.value,
                    status="not_found", url=url, http_status=200,
                    confidence="medium",
                    evidence=f"No court documents matched '{query}'.",
                ),
            )
        findings: list[Finding] = []
        for item in rows[:5]:
            metadata = {
                "case_name": _clean(item.get("caseName"))[:200],
                "court": _clean(item.get("court_citation_string") or item.get("court")),
                "docket_number": _clean(item.get("docketNumber")),
                "date_filed": str(item.get("dateFiled") or "")[:10],
                "document_type": str(item.get("document_type") or ""),
                "snippet": _clean(_strip_tags(str(item.get("snippet") or "")), limit=250),
            }
            metadata = {k: v for k, v in metadata.items() if v}
            findings.append(
                Finding(
                    module=self.name, source="cl-document", target=target.value,
                    status="candidate",
                    url=str(item.get("absolute_url") or "").strip()
                    or CL_PROFILE_BASE,
                    title=_clean(item.get("caseName"))[:150] or "Untitled filing",
                    http_status=200, confidence="low",
                    evidence=(
                        "Public court-record match; verify the document before "
                        "attributing anything to a specific person or company."
                    ),
                    metadata={"query": query, **metadata},
                )
            )
        return tuple(findings)


def _json_dict(result):
    import json

    try:
        payload = json.loads(result.body_text)
    except Exception:  # noqa: BLE001
        return None
    return payload if isinstance(payload, dict) else None


def _strip_tags(text: str) -> str:
    import html as html_mod
    import re as re_mod

    return re_mod.sub(r"<[^>]+>", "", html_mod.unescape(text))
