from __future__ import annotations

from ..engine import Finding, RunConfig, ScanTarget


class DeepLeaksModule:
    """Search user-supplied local leak datasets (offline sqlite index).

    Import first:

        python -m osintkit leaks-import <file-or-dir>

    Exact-token match plus raw-line substring fallback. Nothing leaves
    the machine: this is a local grep with an index.
    """

    name = "deep-leaks"
    supported_targets = ("email", "phone", "username", "person")

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        try:
            from osintkit import store
            if not store.DB_PATH.exists():
                return (Finding(
                    module=self.name, source="osintkit.store", target=target.value,
                    status="planned", confidence="low",
                    evidence="No local leak index — import datasets with: "
                             "python -m osintkit leaks-import <path>"),)
            hits = store.search_leaks(target.value)
        except Exception as exc:  # noqa: BLE001
            return (Finding(module=self.name, source="osintkit.store",
                            target=target.value, status="skipped",
                            confidence="low", evidence=str(exc)),)

        by_source: dict[str, list[dict]] = {}
        for h in hits[:50]:
            by_source.setdefault(h.get("source") or "unknown", []).append(h)

        out: list[Finding] = []
        for src, items in sorted(by_source.items()):
            kinds = ", ".join(sorted({i.get("kind", "?") for i in items}))
            sample = items[0].get("value", "")
            out.append(Finding(
                module=self.name, source=src, target=target.value,
                status="hit", confidence="high",
                evidence=f"{len(items)} hit(s) [{kinds}], e.g. '{sample}'",
                metadata={"matches": ", ".join(i.get("value", "") for i in items[:15])}))
        if not out:
            out.append(Finding(module=self.name, source="local-index",
                               target=target.value, status="not_found",
                               confidence="medium",
                               evidence="No matches in local leak index"))
        return tuple(out)
