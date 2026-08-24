from __future__ import annotations

from dataclasses import dataclass

from .engine import Engine
from .modules import (
    DomainScanModule,
    EmailScanModule,
    InstagramPublicProfileModule,
    PersonNameScanModule,
    PhoneScanModule,
    RuUaSourcePackModule,
    SocialPublicProfileModule,
    TelegramScanModule,
    UsernameScanModule,
    WebMetadataModule,
)
from .modules.breach_intel import HibpBreachModule, PsbdmpDumpModule
from .modules.company_intel import CompaniesHouseModule, GleifCompanyModule
from .modules.deep_leaks import DeepLeaksModule
from .modules.deep_sanctions import SanctionsIndexModule
from .modules.domain_intel import (
    DomainsdbSearchModule,
    InternetDbModule,
    IpGeoModule,
    OtxPassiveDnsModule,
    OtxReputationModule,
    PassiveDnsModule,
    UrlscanSearchModule,
    WaybackCdxModule,
)
from .modules.dorks import DorksModule
from .modules.email_intel import EmailQualityModule
from .modules.exif_photo import ExifPhotoModule
from .modules.legal_intel import CourtListenerModule
from .modules.person_sources import (
    BlueskyProfileModule,
    GithubCommitEmailsModule,
    GitHubUserModule,
    MastodonLookupModule,
    PredictasearchModule,
    WikidataPersonModule,
)
from .modules.telegram_intel import BotsArchiveModule


@dataclass(frozen=True)
class ModuleDescriptor:
    """Registry metadata for one native module.

    Lets profiles select concrete modules and lets plans show exactly what
    will run, whether it touches the network, and what it requires.
    """

    instance: object
    network_access: bool                 # does live mode perform requests?
    risk_tier: str                       # "passive" | "active"
    data_sensitivity: str = "public"     # class of data the source holds
    requires_index: bool = False         # needs a locally built index first
    requires_key: bool = False           # needs an operator-provided API key
    key_env: str = ""
    api_endpoint: str = ""               # provenance: documented API base/endpoint
    last_live_check: str = ""            # date of the last verified live run
    dry_run_evidence: bool = False       # offline generators may assert in dry-run

    @property
    def module_id(self) -> str:
        return self.instance.name  # type: ignore[attr-defined]

    @property
    def target_kinds(self) -> tuple[str, ...]:
        return tuple(self.instance.supported_targets)  # type: ignore[attr-defined]

    def to_dict(self) -> dict[str, object]:
        return {
            "module_id": self.module_id,
            "target_kinds": list(self.target_kinds),
            "network_access": self.network_access,
            "risk_tier": self.risk_tier,
            "data_sensitivity": self.data_sensitivity,
            "requires_index": self.requires_index,
            "requires_key": self.requires_key,
            "key_env": self.key_env,
            "api_endpoint": self.api_endpoint,
            "last_live_check": self.last_live_check,
            "dry_run_evidence": self.dry_run_evidence,
        }


def _d(instance: object, *, network: bool, tier: str, sensitivity: str = "public",
       index: bool = False, key: bool = False, key_env: str = "",
       api: str = "", last_check: str = "", dry_evidence: bool = False) -> ModuleDescriptor:
    return ModuleDescriptor(
        instance=instance,
        network_access=network,
        risk_tier=tier,
        data_sensitivity=sensitivity,
        requires_index=index,
        requires_key=key,
        key_env=key_env,
        api_endpoint=api,
        last_live_check=last_check,
        dry_run_evidence=dry_evidence,
    )


MODULE_DESCRIPTORS: tuple[ModuleDescriptor, ...] = (
    _d(UsernameScanModule(), network=True, tier="active"),
    _d(PersonNameScanModule(), network=False, tier="passive"),
    _d(EmailScanModule(), network=True, tier="active"),
    _d(PhoneScanModule(), network=False, tier="passive"),
    _d(DomainScanModule(), network=True, tier="active"),
    _d(WebMetadataModule(), network=True, tier="active"),
    _d(TelegramScanModule(), network=True, tier="active", sensitivity="public_social"),
    _d(InstagramPublicProfileModule(), network=True, tier="active", sensitivity="public_social"),
    _d(SocialPublicProfileModule(), network=True, tier="active", sensitivity="public_social"),
    _d(RuUaSourcePackModule(), network=False, tier="passive", dry_evidence=True),
    _d(SanctionsIndexModule(), network=False, tier="passive", sensitivity="watchlist", index=True),
    _d(DeepLeaksModule(), network=False, tier="passive", sensitivity="breach_derived", index=True),
    _d(DorksModule(), network=False, tier="passive"),
    _d(ExifPhotoModule(), network=True, tier="active"),
    _d(GitHubUserModule(), network=True, tier="active", sensitivity="self_published"),
    _d(GithubCommitEmailsModule(), network=True, tier="active", sensitivity="self_published"),
    _d(PredictasearchModule(), network=True, tier="active",
       sensitivity="public_social", key=True, key_env="PREDICTASEARCH_API_KEY"),
    _d(MastodonLookupModule(), network=True, tier="active", sensitivity="self_published"),
    _d(BlueskyProfileModule(), network=True, tier="active", sensitivity="self_published"),
    _d(WikidataPersonModule(), network=True, tier="active"),
    _d(InternetDbModule(), network=True, tier="passive"),
    _d(WaybackCdxModule(), network=True, tier="passive"),
    _d(UrlscanSearchModule(), network=True, tier="passive", key=True, key_env="URLSCAN_API_KEY"),
    _d(GleifCompanyModule(), network=True, tier="passive"),
    _d(PassiveDnsModule(), network=True, tier="passive"),
    _d(CompaniesHouseModule(), network=True, tier="passive",
       key=True, key_env="COMPANIES_HOUSE_API_KEY"),
    _d(IpGeoModule(), network=True, tier="passive"),
    _d(DomainsdbSearchModule(), network=True, tier="passive"),
    _d(EmailQualityModule(), network=True, tier="passive",
       sensitivity="self_published"),
    _d(HibpBreachModule(), network=True, tier="passive",
       sensitivity="breach_metadata", key=True, key_env="HIBP_API_KEY"),
    _d(PsbdmpDumpModule(), network=True, tier="active",
       sensitivity="breach_derived"),
    _d(CourtListenerModule(), network=True, tier="passive",
       key=True, key_env="COURTLISTENER_API_KEY"),
    _d(OtxPassiveDnsModule(), network=True, tier="passive",
       key=True, key_env="OTX_API_KEY"),
    _d(OtxReputationModule(), network=True, tier="passive",
       key=True, key_env="OTX_API_KEY"),
    _d(BotsArchiveModule(), network=True, tier="passive"),
)


# Documented upstream API provenance per module (review: supply-chain/provenance).
_API_PROVENANCE = {
    "github-user": "https://api.github.com/users/{user}",
    "github-commit-emails": "https://api.github.com/users/{user}/repos",
    "mastodon-lookup": "https://{instance}/api/v1/accounts/lookup",
    "bluesky-profile": "https://api.bsky.app/xrpc/app.bsky.actor.getProfile",
    "wikidata-person": "https://www.wikidata.org/w/api.php",
    "internetdb-ip": "https://internetdb.shodan.io/{ip}",
    "wayback-cdx": "https://web.archive.org/cdx/search/cdx",
    "urlscan-search": "https://urlscan.io/api/v1/search/",
    "ip-api-geo": "http://ip-api.com/json/{ip}",
    "domainsdb-search": "https://api.domainsdb.info/v1/domains/search",
    "email-quality": "https://eva.pingutil.com/email",
    "gleif-company": "https://api.gleif.org/api/v1/entities",
    "companies-house": "https://api.company-information.service.gov.uk/search/companies",
    "courtlistener-search": "https://www.courtlistener.com/api/rest/v4/search/",
    "otx-passive-dns": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
    "otx-reputation": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
    "hibp-breaches": "https://haveibeenpwned.com/api/v3/breachedaccount/{account}",
    "psbdmp-dumps": "https://psbdmp.ws/api/search/{term}",
    "botsarchive-bot": "https://api.botsarchive.com/getBotID.php",
}

MODULE_DESCRIPTORS = tuple(
    (
        __import__("dataclasses").replace(d, api_endpoint=_API_PROVENANCE.get(d.module_id, ""))
        if d.module_id in _API_PROVENANCE
        else d
    )
    for d in MODULE_DESCRIPTORS
)
MODULE_DESCRIPTOR_MAP: dict[str, ModuleDescriptor] = {
    descriptor.module_id: descriptor for descriptor in MODULE_DESCRIPTORS
}


def build_default_engine() -> Engine:
    return Engine([descriptor.instance for descriptor in MODULE_DESCRIPTORS])


def module_ids_for_kind(target_kind: str) -> tuple[str, ...]:
    return tuple(
        descriptor.module_id
        for descriptor in MODULE_DESCRIPTORS
        if target_kind in descriptor.target_kinds
    )


def descriptors_for_profile_modules(module_ids: tuple[str, ...]) -> list[dict[str, object]]:
    """Plan payload rows for the concrete modules a profile will execute."""
    rows: list[dict[str, object]] = []
    for module_id in module_ids:
        descriptor = MODULE_DESCRIPTOR_MAP.get(module_id)
        if descriptor is not None:
            rows.append(descriptor.to_dict())
    return rows
