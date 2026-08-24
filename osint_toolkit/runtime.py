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
from .modules.company_intel import CompaniesHouseModule, GleifCompanyModule
from .modules.deep_leaks import DeepLeaksModule
from .modules.deep_sanctions import SanctionsIndexModule
from .modules.domain_intel import (
    DomainsdbSearchModule,
    InternetDbModule,
    IpGeoModule,
    PassiveDnsModule,
    UrlscanSearchModule,
    WaybackCdxModule,
)
from .modules.dorks import DorksModule
from .modules.email_intel import EmailQualityModule
from .modules.exif_photo import ExifPhotoModule
from .modules.person_sources import (
    BlueskyProfileModule,
    GitHubUserModule,
    MastodonLookupModule,
    WikidataPersonModule,
)


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
        }


def _d(instance: object, *, network: bool, tier: str, sensitivity: str = "public",
       index: bool = False, key: bool = False, key_env: str = "") -> ModuleDescriptor:
    return ModuleDescriptor(
        instance=instance,
        network_access=network,
        risk_tier=tier,
        data_sensitivity=sensitivity,
        requires_index=index,
        requires_key=key,
        key_env=key_env,
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
    _d(RuUaSourcePackModule(), network=False, tier="passive"),
    _d(SanctionsIndexModule(), network=False, tier="passive", sensitivity="watchlist", index=True),
    _d(DeepLeaksModule(), network=False, tier="passive", sensitivity="breach_derived", index=True),
    _d(DorksModule(), network=False, tier="passive"),
    _d(ExifPhotoModule(), network=True, tier="active"),
    _d(GitHubUserModule(), network=True, tier="active", sensitivity="self_published"),
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
