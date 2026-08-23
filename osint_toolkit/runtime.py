from __future__ import annotations

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
from .modules.deep_leaks import DeepLeaksModule
from .modules.deep_sanctions import SanctionsIndexModule
from .modules.domain_intel import InternetDbModule, UrlscanSearchModule, WaybackCdxModule
from .modules.dorks import DorksModule
from .modules.exif_photo import ExifPhotoModule
from .modules.person_sources import (
    BlueskyProfileModule,
    GitHubUserModule,
    MastodonLookupModule,
    WikidataPersonModule,
)


def build_default_engine() -> Engine:
    return Engine(
        [
            UsernameScanModule(),
            PersonNameScanModule(),
            EmailScanModule(),
            PhoneScanModule(),
            DomainScanModule(),
            WebMetadataModule(),
            TelegramScanModule(),
            InstagramPublicProfileModule(),
            SocialPublicProfileModule(),
            RuUaSourcePackModule(),
            SanctionsIndexModule(),
            DeepLeaksModule(),
            DorksModule(),
            ExifPhotoModule(),
            GitHubUserModule(),
            MastodonLookupModule(),
            BlueskyProfileModule(),
            WikidataPersonModule(),
            InternetDbModule(),
            WaybackCdxModule(),
            UrlscanSearchModule(),
        ]
    )
