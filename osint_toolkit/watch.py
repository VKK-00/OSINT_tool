"""Unified watch: scheduled re-scans with entity-level diffing.

Each cycle runs the same investigation for fixed targets, overwrites the
live case in the shared store, and reports which entities appeared since
the previous cycle. Designed to be driven by the ``watch`` CLI command
(single shot with ``--once``, or an interval loop).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .case_store import CaseStore
from .engine import ScanTarget
from .entities import Entity
from .investigation import InvestigationResult, run_investigation


@dataclass(frozen=True)
class WatchCycle:
    watch_id: str
    cycle_number: int
    total_entities: int
    new_entities: tuple[Entity, ...]
    findings_count: int
    generated_at: str


def _entity_key_list(entities: tuple[Entity, ...]) -> list[list[str]]:
    return sorted([entity.kind, entity.value.lower()] for entity in entities)


def compute_new_entities(
    previous_keys: list[list[str]],
    current: tuple[Entity, ...],
) -> tuple[Entity, ...]:
    """Entities present now but absent from the previous cycle snapshot."""
    previous = {tuple(key) for key in previous_keys}
    return tuple(
        entity
        for entity in sorted(current, key=lambda e: (e.kind, e.value.lower()))
        if (entity.kind, entity.value.lower()) not in previous
    )


class WatchRunner:
    """Runs watch cycles against the shared case store."""

    def __init__(
        self,
        case_store: CaseStore,
        *,
        live: bool = True,
        timeout: float = 10.0,
        http_workers: int = 1,
        request_delay: float = 0.0,
    ):
        self.store = case_store
        self.live = live
        self.timeout = timeout
        self.http_workers = http_workers
        self.request_delay = request_delay

    def run_cycle(
        self,
        watch_id: str,
        targets: tuple[ScanTarget, ...],
        *,
        allowed_native_modules: tuple[str, ...] | None = None,
        native_kinds: tuple[str, ...] | None = None,
        title: str = "Watch",
    ) -> WatchCycle:
        result: InvestigationResult = run_investigation(
            targets,
            title=title,
            live=self.live,
            timeout=self.timeout,
            http_workers=self.http_workers,
            request_delay=self.request_delay,
            native_kinds=native_kinds,
            allowed_native_modules=allowed_native_modules,
        )

        state = self.store.get_watch_state(watch_id)
        previous_keys: list[list[str]] = (
            list(state["entity_keys"]) if state else []
        )
        new_entities = compute_new_entities(previous_keys, result.entities)
        cycle_number = (int(state["cycle_count"]) if state else 0) + 1
        now = datetime.now().astimezone().isoformat(timespec="seconds")

        # the watch owns one live case that is overwritten every cycle
        self.store.save(result, case_id=watch_id)

        self.store.set_watch_state(
            watch_id,
            targets=targets,
            entity_keys=_entity_key_list(result.entities),
            last_run_at=now,
            cycle_count=cycle_number,
        )
        return WatchCycle(
            watch_id=watch_id,
            cycle_number=cycle_number,
            total_entities=len(result.entities),
            new_entities=new_entities,
            findings_count=len(result.all_findings()),
            generated_at=result.generated_at,
        )


__all__ = ["WatchCycle", "WatchRunner", "compute_new_entities"]
