from __future__ import annotations

from dataclasses import dataclass

from ..engine import Finding, RunConfig, ScanTarget


@dataclass(frozen=True)
class RuUaSource:
    name: str
    url: str
    category: str
    region: str
    note: str
    upstream_refs: tuple[str, ...]


RU_UA_SOURCES: tuple[RuUaSource, ...] = (
    RuUaSource(
        "DeepStateMap",
        "https://deepstatemap.live/",
        "conflict-map",
        "ua",
        "Ukraine frontline/conflict map source referenced by Shadowbroker.",
        ("BigBodyCobain/Shadowbroker",),
    ),
    RuUaSource(
        "Liveuamap Ukraine",
        "https://liveuamap.com/",
        "conflict-map",
        "ua",
        "Ukraine interactive map resource referenced by OSINT lists.",
        ("Astrosp/Awesome-OSINT-List",),
    ),
    RuUaSource(
        "TGStat RU",
        "https://tgstat.ru/",
        "telegram-analytics",
        "ru",
        "Russian Telegram analytics/search resource referenced by Telegram/SOCMINT lists.",
        ("ItIsMeCall911/Awesome-Telegram-OSINT", "osintambition/Social-Media-OSINT-Tools-Collection"),
    ),
    RuUaSource(
        "VK",
        "https://vk.com/",
        "social-platform",
        "ru",
        "VKontakte platform/API appears across RU-oriented OSINT resources.",
        ("cipher387/API-s-for-OSINT", "snooppr/snoop"),
    ),
    RuUaSource(
        "Odnoklassniki",
        "https://ok.ru/",
        "social-platform",
        "ru",
        "Odnoklassniki API/platform source in RU-oriented OSINT API lists.",
        ("cipher387/API-s-for-OSINT",),
    ),
    RuUaSource(
        "Yandex",
        "https://yandex.com/",
        "search-platform",
        "ru",
        "Yandex search/dorks/trends resources appear in multiple OSINT lists.",
        ("jivoi/awesome-osint", "cipher387/Dorks-collections-list", "Jieyab89/OSINT-Cheat-sheet"),
    ),
    RuUaSource(
        "Mail.ru",
        "https://mail.ru/",
        "platform",
        "ru",
        "mail.ru appears in account/email-related source lists; use only within lawful scope.",
        ("megadose/holehe",),
    ),
    RuUaSource(
        "Geocam.ru",
        "https://www.geocam.ru/en/",
        "geospatial",
        "ru",
        "Webcam/geospatial resource referenced by hacker search engine lists.",
        ("edoardottt/awesome-hacker-search-engines",),
    ),
    RuUaSource(
        "paste.in.ua",
        "https://paste.in.ua/",
        "pastebin",
        "ua",
        "Ukrainian pastebin resource referenced by awesome-osint.",
        ("jivoi/awesome-osint",),
    ),
    # --- public registries (open personal/legal data, lawful-scope pivots) ---
    RuUaSource(
        "UA Court Register",
        "https://reyestr.court.gov.ua/",
        "public-registry",
        "ua",
        "Unified state register of Ukrainian court decisions; searchable by person or company name within lawful scope.",
        ("cipher387/osint_stuff_tool_collection",),
    ),
    RuUaSource(
        "UA Open Data Portal",
        "https://data.gov.ua/",
        "public-registry",
        "ua",
        "Ukrainian national open-data portal, including EDR and public-sector datasets.",
        ("cipher387/osint_stuff_tool_collection",),
    ),
    RuUaSource(
        "UA EDR Open Data",
        "https://data.gov.ua/dataset/c0f0c4e7-dc84-4ecd-a119-03e6c9ff72a9",
        "public-registry",
        "ua",
        "Open dataset of the Unified State Register of Ukrainian legal entities and individual entrepreneurs (EDR/ФОП).",
        ("local-curation",),
    ),
    RuUaSource(
        "RF EGRUL/EGRIP",
        "https://egrul.nalog.ru/",
        "public-registry",
        "ru",
        "Russian Federal Tax Service open register of legal entities and sole proprietors; free short report per entity.",
        ("cipher387/osint_stuff_tool_collection",),
    ),
    RuUaSource(
        "Fedresurs",
        "https://fedresurs.ru/",
        "public-registry",
        "ru",
        "Russian federal resource of legally significant publications: bankruptcies, pledges, liquidation notices.",
        ("local-curation",),
    ),
    # --- telegram channel catalogs (public search surfaces) ---
    RuUaSource(
        "Telegago (Google CSE)",
        "https://cse.google.com/cse?q=+&cx=006368593537057042503:efxu7xprihg",
        "telegram-catalog",
        "ru-ua",
        "Google Custom Search scoped to t.me - the widest public Telegram channel/group search surface.",
        ("cipher387/osint_stuff_tool_collection",),
    ),
    RuUaSource(
        "TG.World",
        "https://tg.world/",
        "telegram-catalog",
        "ru-ua",
        "Global search system for public Telegram channels, groups and bots.",
        ("local-curation",),
    ),
    RuUaSource(
        "Teleteg",
        "https://teleteg.com/",
        "telegram-catalog",
        "ru-ua",
        "Public Telegram search engine for channels and groups.",
        ("local-curation",),
    ),
    # --- legal / leaks-of-record databases (person & company pivots) ---
    RuUaSource(
        "CourtListener RECAP",
        "https://www.courtlistener.com/recap/",
        "legal-database",
        "global",
        "Free archive of US federal court documents (PACER mirror); useful for company and person pivots.",
        ("jivoi/awesome-osint",),
    ),
    RuUaSource(
        "ICIJ Offshore Leaks",
        "https://offshoreleaks.icij.org/",
        "legal-database",
        "global",
        "Searchable ICIJ database of offshore entities, officers and intermediaries from leaked registry filings.",
        ("jivoi/awesome-osint",),
    ),
)


@dataclass(frozen=True)
class RuUaSourcePackModule:
    name: str = "ru-ua-source-pack"
    supported_targets: tuple[str, ...] = ("ru-ua",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        del config
        selector = target.value.strip().lower() or "all"
        sources = filter_sources(selector, target.region)
        if not sources:
            return (
                Finding(
                    module=self.name,
                    source="source-pack",
                    target=target.value,
                    status="not_found",
                    confidence="high",
                    evidence="No RU/UA source-pack entries matched the selector.",
                ),
            )
        return tuple(source_to_finding(self.name, target.value, source) for source in sources)


def filter_sources(selector: str, region: str) -> tuple[RuUaSource, ...]:
    matched: list[RuUaSource] = []
    for source in RU_UA_SOURCES:
        if region in {"ru", "ua"} and source.region != region:
            continue
        if selector in {"all", "ru-ua", "russia-ukraine"}:
            matched.append(source)
        elif selector in {source.region, source.category.lower()}:
            matched.append(source)
        elif selector == "platforms" and "platform" in source.category.lower():
            matched.append(source)
        elif selector == "maps" and "map" in source.category.lower():
            matched.append(source)
        elif selector in source.name.lower() or selector in source.note.lower():
            matched.append(source)
    return tuple(matched)


def source_to_finding(module: str, target: str, source: RuUaSource) -> Finding:
    return Finding(
        module=module,
        source=source.name,
        target=target,
        status="reference",
        url=source.url,
        confidence="curated",
        evidence=source.note,
        metadata={
            "category": source.category,
            "region": source.region,
            "upstream_refs": ", ".join(source.upstream_refs),
        },
    )
