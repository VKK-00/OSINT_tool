from __future__ import annotations

from ..engine import Finding, RunConfig, ScanTarget


class SanctionsIndexModule:
    """Offline watchlist search over a local OpenSanctions simplecsv index.

    The index is opt-in and built with:

        python -m osintkit sanctions-update

    (stores sqlite at out/index.db; ~1.2M entities from OFAC/EU/UA NSDC
    and other lists via the OpenSanctions "default" dataset).
    """

    name = "sanctions-index"
    supported_targets = ("person", "username", "ru-ua")

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        try:
            from osintkit import store
            if not store.sanctions_ready():
                return (Finding(
                    module=self.name, source="osintkit.store", target=target.value,
                    status="planned", confidence="low",
                    evidence="Sanctions index is empty — build it once with: "
                             "python -m osintkit sanctions-update"),)
            hits = store.search_sanctions(target.value)
        except Exception as exc:  # noqa: BLE001 — index problems must not kill a scan
            return (Finding(module=self.name, source="osintkit.store",
                            target=target.value, status="skipped",
                            confidence="low", evidence=str(exc)),)

        out: list[Finding] = []
        for h in hits[:20]:
            bits = [b for b in (h.get("schema"), h.get("countries"),
                                h.get("topics"), h.get("birth_date")) if b]
            title = h["name"] + (" · " + " · ".join(bits) if bits else "")
            notes = (h.get("notes") or "")[:300]
            out.append(Finding(
                module=self.name, source="opensanctions-local", target=target.value,
                status="hit", url=(
                    "https://www.opensanctions.org/search/?q="
                    + urllib_quote(h["name"])),
                title=title,
                confidence="medium", evidence=notes,
                metadata={"schema": h.get("schema", ""),
                          "countries": h.get("countries", ""),
                          "topics": h.get("topics", ""),
                          "birth_date": h.get("birth_date", "")}))
        if not out:
            out.append(Finding(module=self.name, source="opensanctions-local",
                               target=target.value, status="not_found",
                               confidence="low",
                               evidence="No watchlist matches"))
        return tuple(out)


def urllib_quote(value: str) -> str:
    import urllib.parse
    return urllib.parse.quote(value)
