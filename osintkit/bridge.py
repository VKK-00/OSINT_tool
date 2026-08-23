"""Bridge layer: adapt osint_toolkit engine findings to osintkit reports.

Single place where engine.Finding -> core.Finding conversion lives, per
docs/CONTRACT.md. osintkit modules must not re-implement scan logic; they
delegate to osint_toolkit modules and convert results through this module.
"""
from __future__ import annotations

import os
from typing import Any

from osint_toolkit.engine import Finding as EngineFinding
from osint_toolkit.engine import RunConfig, ScanTarget


def build_run_config(*, live: bool = True, min_request_delay: float = 0.0) -> RunConfig:
    """RunConfig for bridge scans, honouring the legacy OSINTKIT_* env knobs."""
    try:
        delay = float(os.environ.get("OSINTKIT_REQUEST_DELAY", "0"))
    except ValueError:
        delay = 0.0
    return RunConfig(
        live=live,
        timeout=15.0,
        http_retries=1,
        request_delay=max(delay, min_request_delay, 0.0),
    )


def classify_target(value: str) -> str:
    """Map a raw legacy target string onto an engine target kind."""
    stripped = value.strip()
    if "@" in stripped:
        return "email"
    if stripped.lstrip("+").isdigit():
        return "phone"
    if stripped.startswith("http"):
        return "url"
    return "username"


_CONFIDENCE_FALLBACK = {"unknown": "low", "not_checked": "low"}


def engine_to_core(finding: EngineFinding, *, source_suffix: str = "") -> tuple[str, dict[str, Any]]:
    """Convert one engine finding into (kind, extra-fields) pieces.

    Returns the core ``kind`` and the ``extra`` payload; callers attach their
    own module/source/value so report labels stay stable.
    """
    kind_by_module = {
        "dorks": "dork",
        "telegram-baseline": _telegram_kind(finding),
    }
    kind = kind_by_module.get(finding.module, "profile")
    extra: dict[str, Any] = {
        key: value for key, value in finding.metadata.items() if not key.startswith("messages_")
    }
    if finding.title:
        extra["title"] = finding.title[:120]
    if finding.status:
        extra["status"] = finding.status
    if finding.http_status is not None:
        extra["http_status"] = finding.http_status
    extra.setdefault("engine_target", finding.target)
    if source_suffix:
        extra["variant"] = source_suffix
    return kind, extra


def core_confidence(finding: EngineFinding) -> str:
    return _CONFIDENCE_FALLBACK.get(finding.confidence, finding.confidence)


def scan_target(value: str, kind: str | None = None) -> ScanTarget:
    return ScanTarget(kind=kind or classify_target(value), value=value)


def core_to_engine(finding, *, target: str) -> EngineFinding:
    """Convert a legacy core Finding into the unified engine model."""
    return EngineFinding(
        module=finding.source or "osintkit",
        source=str(finding.kind),
        target=target,
        status="candidate",
        url=finding.url or "",
        title=str(finding.value)[:200],
        http_status=None,
        confidence=finding.confidence
        if finding.confidence in {"low", "medium", "high"}
        else "low",
        evidence=str(finding.value),
        metadata={
            str(key): str(value)
            for key, value in (finding.extra or {}).items()
            if isinstance(value, (str, int, float, bool))
        },
    )


def _telegram_kind(finding: EngineFinding) -> str:
    mapping = {
        "channel": "channel",
        "post": "post",
        "history": "history",
        "handle": "profile",
    }
    return mapping.get(str(finding.metadata.get("target_type")), "profile")
