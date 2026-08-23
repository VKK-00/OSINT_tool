"""Company/legal-entity intelligence from public registries.

- GLEIF: open LEI database, no key required;
- UK Companies House: free API key required (COMPANIES_HOUSE_API_KEY).

These start the company investigation direction; they pair with the UA/RF
public registries in the ru-ua source pack.
"""
from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass
from urllib.parse import quote

from ..engine import Finding, RunConfig, ScanTarget
from .person_sources import _json_object  # shared defensive JSON helper

GLEIF_API = "https://api.gleif.org/api/v1/entities"
LEI_RE_STRICT = re.compile(r"^[A-Z0-9]{20}$")
COMPANIES_HOUSE_SEARCH_URL = (
    "https://api.company-information.service.gov.uk/search/companies"
)


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


@dataclass(frozen=True)
class CompaniesHouseModule:
    """UK Companies House company search (free API key, Basic auth)."""

    name: str = "companies-house"
    supported_targets: tuple[str, ...] = ("company",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        query = target.value.strip().strip('"')
        api_key = os.environ.get("COMPANIES_HOUSE_API_KEY", "").strip()
        url = f"{COMPANIES_HOUSE_SEARCH_URL}?q={quote(query)}&items_per_page=5"
        if not api_key:
            return (
                Finding(
                    module=self.name, source="ch-api", target=target.value,
                    status="skipped", confidence="high",
                    evidence=(
                        "COMPANIES_HOUSE_API_KEY is not set; register free at "
                        "https://developer.company-information.service.gov.uk/ to enable UK registry search."
                    ),
                ),
            )
        if len(query) < 2:
            return (
                Finding(
                    module=self.name, source="normalizer", target=target.value,
                    status="invalid", confidence="high",
                    evidence="Company name is too short for Companies House search.",
                ),
            )
        if not config.live:
            return (
                Finding(
                    module=self.name, source="ch-api", target=target.value,
                    status="planned", url=url, confidence="not_checked",
                    evidence="Dry run only. Pass --live to search the UK Companies House register.",
                ),
            )
        client = _client(config)
        token = base64.b64encode(f"{api_key}:".encode()).decode()
        result = client.check(url, headers={"Authorization": f"Basic {token}"})
        payload = _json_object(result) if result.status_code == 200 else None
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            return (
                Finding(
                    module=self.name, source="ch-api", target=target.value,
                    status="unknown", http_status=result.status_code,
                    confidence="low",
                    evidence=result.error or f"HTTP {result.status_code} from Companies House.",
                ),
            )
        companies = parse_companies_house(payload)
        if not companies:
            return (
                Finding(
                    module=self.name, source="ch-api", target=target.value,
                    status="not_found", url=url, http_status=200,
                    confidence="medium",
                    evidence=f"No Companies House entries matched '{query}'.",
                ),
            )
        findings: list[Finding] = []
        for company in companies[:5]:
            number = str(company.get("company_number") or "")
            findings.append(
                Finding(
                    module=self.name, source="ch-company", target=target.value,
                    status="candidate",
                    url=(
                        "https://find-and-update.company-information.service.gov.uk/company/"
                        + quote(number, safe="")
                    ) if number else url,
                    title=str(company.get("title") or query),
                    http_status=200, confidence="medium",
                    evidence="UK Companies House register entry.",
                    metadata=company,
                )
            )
        return tuple(findings)


def parse_companies_house(payload: dict) -> tuple[dict[str, str], ...]:
    """Extract flat company summaries from a Companies House search response."""
    items = payload.get("items")
    if not isinstance(items, list):
        return ()
    out: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        address = item.get("address") if isinstance(item.get("address"), dict) else {}
        parts = [
            str(address.get(key) or "").strip()
            for key in ("premises", "address_line_1", "locality", "postal_code", "country")
        ]
        meta: dict[str, str] = {
            "company_number": str(item.get("company_number") or ""),
            "legal_name": str(item.get("title") or "")[:200],
            "status": str(item.get("company_status") or ""),
            "kind": str(item.get("company_type") or ""),
            "incorporated_at": str(item.get("date_of_creation") or ""),
            "address": ", ".join(part for part in parts if part)[:250],
        }
        out.append({key: value for key, value in meta.items() if value})
    return tuple(out)
