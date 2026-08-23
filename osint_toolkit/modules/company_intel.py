"""Company/legal-entity intelligence from the public GLEIF API.

GLEIF (Global Legal Entity Identifier Foundation) publishes open data for
every issued LEI: legal name, address country/city, legal form, status.
No key required. This starts the company investigation direction; it pairs
with the UA/RF public registries in the ru-ua source pack.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

from ..engine import Finding, RunConfig, ScanTarget
from .person_sources import _json_object  # shared defensive JSON helper

GLEIF_API = "https://api.gleif.org/api/v1/entities"
LEI_RE_STRICT = re.compile(r"^[A-Z0-9]{20}$")


@dataclass(frozen=True)
class GleifCompanyModule:
    name: str = "gleif-company"
    supported_targets: tuple[str, ...] = ("company",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        query = target.value.strip().strip('"')
        if len(query) < 2:
            return (
                Finding(
                    module=self.name, source="normalizer", target=target.value,
                    status="invalid", confidence="high",
                    evidence="Company name or LEI is too short for GLEIF lookup.",
                ),
            )
        is_lei = bool(LEI_RE_STRICT.fullmatch(query.upper()))
        if is_lei:
            url = f"{GLEIF_API}/?filter[lei]={quote(query.upper())}"
        else:
            url = f"{GLEIF_API}/?page[size]=5&filter.entity.searchNames={quote(query)}"
        if not config.live:
            return (
                Finding(
                    module=self.name, source="gleif-api", target=target.value,
                    status="planned", url=url, confidence="not_checked",
                    evidence=(
                        "Dry run only. Pass --live to search the open GLEIF "
                        "legal-entity database."
                    ),
                ),
            )
        client = _client(config)
        result = client.check(url)
        payload = _json_object(result) if result.status_code == 200 else None
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            return (
                Finding(
                    module=self.name, source="gleif-api", target=target.value,
                    status="unknown", http_status=result.status_code,
                    confidence="low",
                    evidence=result.error or f"HTTP {result.status_code} from GLEIF.",
                ),
            )
        entities = parse_gleif_entities(payload)
        if not entities:
            return (
                Finding(
                    module=self.name, source="gleif-api", target=target.value,
                    status="not_found", url=url, http_status=200,
                    confidence="medium",
                    evidence=f"No GLEIF legal entity matched '{query}'.",
                ),
            )
        findings: list[Finding] = []
        for entity in entities[:5]:
            findings.append(
                Finding(
                    module=self.name, source="gleif-entity", target=target.value,
                    status="candidate",
                    url=f"https://search.gleif.org/#/record/{entity.get('lei', '')}",
                    title=str(entity.get("legal_name") or entity.get("lei") or query),
                    http_status=200, confidence="medium",
                    evidence="Open GLEIF record for this legal entity.",
                    metadata=entity,
                )
            )
        return tuple(findings)


def _client(config: RunConfig):
    from ..http_client import HttpClient

    return HttpClient(
        timeout=config.timeout,
        user_agent=config.user_agent,
        retries=config.http_retries,
        backoff_seconds=config.http_backoff,
    )


def parse_gleif_entities(payload: dict) -> tuple[dict[str, str], ...]:
    """Extract flat entity summaries from a GLEIF API list response."""
    data = payload.get("data")
    if not isinstance(data, list):
        return ()
    out: list[dict[str, str]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        attributes = item.get("attributes")
        if not isinstance(attributes, dict):
            continue
        entity = attributes.get("entity")
        addresses = attributes.get("legalAddress")
        if not isinstance(entity, dict):
            entity = {}
        legal_name_obj = entity.get("legalName")
        legal_name = (
            legal_name_obj.get("name") if isinstance(legal_name_obj, dict) else None
        ) or (str(legal_name_obj) if legal_name_obj else "")
        meta: dict[str, str] = {"lei": str(attributes.get("lei") or "")}
        meta["legal_name"] = str(legal_name or "")[:200]
        meta["status"] = str(entity.get("status") or "")
        legal_form = entity.get("legalForm")
        if isinstance(legal_form, dict):
            meta["legal_form"] = str(legal_form.get("name") or "")
        if isinstance(addresses, dict):
            meta["country"] = str(addresses.get("country") or "")
            meta["city"] = str(addresses.get("city") or "")
        meta["registered_at"] = str(entity.get("registration", {}).get("initialRegistrationDate") or "")[:10]
        out.append({key: value.strip() for key, value in meta.items() if value and value.strip()})
    return tuple(out)
