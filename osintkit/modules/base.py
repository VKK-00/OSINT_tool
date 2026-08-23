from __future__ import annotations

import abc
from osintkit.core import Finding, HttpClient, ModuleResult


class Module(abc.ABC):
    """Base class for all osintkit modules."""
    name: str = "base"
    help: str = ""
    target_hint: str = ""   # what kind of target it expects

    @abc.abstractmethod
    async def run(self, target: str, http: HttpClient) -> list[Finding]: ...

    async def safe_run(self, target: str, http: HttpClient) -> ModuleResult:
        import time
        res = ModuleResult(module=self.name, target=target)
        t0 = time.monotonic()
        try:
            res.findings = [f for f in await self.run(target, http) if f]
        except Exception as exc:  # noqa: BLE001 — one bad source must not kill the scan
            res.ok = False
            res.error = f"{type(exc).__name__}: {exc}"
        res.elapsed_s = time.monotonic() - t0
        return res


REGISTRY: dict[str, Module] = {}


def register(cls: type[Module]) -> type[Module]:
    REGISTRY[cls.name] = cls()
    return cls


def get_all() -> list[Module]:
    # import side-effects register everything
    from osintkit.modules import (  # noqa: F401
        username, email_check, phone_info, net_recon,
        telegram, web_archive, geo, leaks, sanctions, dorks, image_osint,
    )
    return list(REGISTRY.values())
