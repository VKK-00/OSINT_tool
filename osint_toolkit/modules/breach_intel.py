"""Breach intelligence modules.

Operator-approved class (see docs/EXTERNAL_INTEGRATIONS.uk.md):
- HIBP official API: which known breaches contain the address, and which
  data classes were affected - never raw passwords;
- psbdmp.ws: pastebin dump IDs matching a term - references only, paste
  contents are fetched manually by the operator if legally justified.

Both live in the deep-full profile next to deep-leaks; neither runs by
default and neither supports bulk mode.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from urllib.parse import quote

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient, HttpResult

HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
PSBDMP_SEARCH_URL = "https://psbdmp.ws/api/search/{term}"
PSBDMP_VIEW_URL = "https://psbdmp.ws/d/{dump_id}"


def _json_list(result: HttpResult) -> list | None:
    try:
        payload = json.loads(result.body_text)
    except (json.JSONDecodeError, TypeError):
        return None
    return payload if isinstance(payload, list) else None


def _json_dict(result: HttpResult) -> dict | None:
    try:
        payload = json.loads(result.body_text)
    except (json.JSONDecodeError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


@dataclass(frozen=True)
class HibpBreachModule:
    """Official HaveIBeenPwned breach-account lookup (operator API key).

    Reports breach names, dates and affected data classes. The API never
    returns passwords, which keeps this on the metadata side of the
    breach-intelligence line.
    """

    name: str = "hibp-breaches"
    supported_targets: tuple[str, ...] = ("email",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        email = target.value.strip()
        url = HIBP_BREACH_URL.format(account=quote(email, safe="@."))
        api_key = os.environ.get("HIBP_API_KEY", "").strip()
        if not api_key:
            return (
                Finding(
                    module=self.name, source="hibp-api", target=email,
                    status="skipped", confidence="high",
                    evidence=(
                        "HIBP_API_KEY is not set; subscribe at "
                        "https://haveibeenpwned.com/API/Key to enable breach-metadata lookups."
                    ),
                ),
            )
        if not config.live:
            return (
                Finding(
                    module=self.name, source="hibp-api", target=email,
                    status="planned", url=url, confidence="not_checked",
                    evidence="Dry run only. Pass --live to query breach metadata.",
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=0, backoff_seconds=config.http_backoff)
        result = client.check(url, headers={
            "hibp-api-key": api_key,
            "Accept": "application/json",
        })
        if result.status_code == 404:
            return (
                Finding(
                    module=self.name, source="hibp-api", target=email,
                    status="not_found", http_status=404, confidence="high",
                    evidence="Address does not appear in any HIBP-indexed breach.",
                ),
            )
        if result.status_code == 401:
            return (
                Finding(
                    module=self.name, source="hibp-api", target=email,
                    status="unknown", http_status=401, confidence="low",
                    evidence="HIBP rejected the API key.",
                ),
            )
        breaches = _json_list(result) if result.status_code == 200 else None
        if breaches is None:
            return (
                Finding(
                    module=self.name, source="hibp-api", target=email,
                    status="unknown", http_status=result.status_code,
                    confidence="low",
                    evidence=(
                        f"HTTP {result.status_code}"
                        + (f": {result.error}" if result.error else "")
                    ),
                ),
            )
        rows: list[str] = []
        data_classes: set[str] = set()
        for breach in breaches:
            if not isinstance(breach, dict):
                continue
            name = str(breach.get("Title") or breach.get("Name") or "?")
            year = str(breach.get("BreachDate") or "")[:4]
            classes = [str(item) for item in breach.get("DataClasses") or []]
            data_classes.update(classes)
            pwn_count = breach.get("PwnCount")
            rows.append(
                f"{name} ({year}; {', '.join(classes)[:80]}"
                + (f"; {pwn_count} accounts)" if pwn_count else ")")
            )
        metadata = {
            "breach_count": str(len(rows)),
            "breaches": " | ".join(rows)[:900],
            "data_classes": ", ".join(sorted(data_classes))[:300],
        }
        return (
            Finding(
                module=self.name, source="hibp-api", target=email,
                status="hit", url=url, http_status=200,
                title=f"HIBP: {len(rows)} known breach(es)",
                confidence="high",
                evidence=(
                    "Official HIBP breach metadata (names, dates, data classes). "
                    "No secret material is included by design."
                ),
                metadata=metadata,
            ),
        )


@dataclass(frozen=True)
class PsbdmpDumpModule:
    """Keyless pastebin-dump reference search via psbdmp.ws.

    Returns dump identifiers and view links only - the operator opens and
    reviews any paste manually, inside their own legal scope.
    """

    name: str = "psbdmp-dumps"
    supported_targets: tuple[str, ...] = ("email", "phone", "username", "domain")

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        term = target.value.strip()
        url = PSBDMP_SEARCH_URL.format(term=quote(term, safe=""))
        if not config.live:
            return (
                Finding(
                    module=self.name, source="psbdmp-api", target=target.value,
                    status="planned", url=url, confidence="not_checked",
                    evidence="Dry run only. Pass --live to search pastebin dump references.",
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        result = client.check(url)
        payload = _json_dict(result) if result.status_code == 200 else None
        dump_ids_raw = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(payload, dict) or not isinstance(dump_ids_raw, list):
            return (
                Finding(
                    module=self.name, source="psbdmp-api", target=target.value,
                    status="unknown", http_status=result.status_code,
                    confidence="low",
                    evidence=result.error or f"HTTP {result.status_code} from psbdmp.ws.",
                ),
            )
        dump_ids = [str(item) for item in dump_ids_raw if str(item).strip()]
        if not dump_ids:
            return (
                Finding(
                    module=self.name, source="psbdmp-api", target=target.value,
                    status="not_found", http_status=200, confidence="medium",
                    evidence=f"No pastebin dumps matched '{term}'.",
                ),
            )
        views = ", ".join(PSBDMP_VIEW_URL.format(dump_id=d) for d in dump_ids[:10])
        return (
            Finding(
                module=self.name, source="psbdmp-api", target=target.value,
                status="candidate", url=url, http_status=200,
                confidence="low",
                title=f"PasteBin dumps referencing target: {len(dump_ids)} found",
                evidence=(
                    "Dump references only. Reviewing paste contents is the "
                    "operator's explicit manual action."
                ),
                metadata={
                    "dump_count": str(len(dump_ids)),
                    "dump_ids": ", ".join(dump_ids[:15]),
                    "view_urls": views,
                },
            ),
        )
