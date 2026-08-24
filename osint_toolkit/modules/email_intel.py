"""Email reputation enrichment from keyless public checkers.

- EVA (pingutil): deliverability / disposable / free-provider classification;
- Kickbox open: disposable-domain flag.

Both are single-address lookups of the same class as the Gravatar profile
check: they answer questions about the mailbox itself without probing
account existence on any social platform.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import quote

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient, HttpResult

EVA_URL = "https://eva.pingutil.com/email?email={email}"
KICKBOX_URL = "https://open.kickbox.com/v1/disposable/{email}"


def _json_dict(result: HttpResult) -> dict | None:
    try:
        payload = json.loads(result.body_text)
    except (json.JSONDecodeError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


@dataclass(frozen=True)
class EmailQualityModule:
    name: str = "email-quality"
    supported_targets: tuple[str, ...] = ("email",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        email = target.value.strip()
        eva_url = EVA_URL.format(email=quote(email, safe=""))
        kickbox_url = KICKBOX_URL.format(email=quote(email, safe=""))
        if not config.live:
            return (
                Finding(
                    module=self.name, source="email-quality", target=email,
                    status="planned", url=eva_url, confidence="not_checked",
                    evidence="Dry run only. Pass --live to query keyless email-reputation APIs.",
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)

        metadata: dict[str, str] = {}
        eva_result = ""
        try:
            eva = client.check(eva_url)
            payload = _json_dict(eva) if eva.status_code == 200 else None
            if isinstance(payload, dict):
                data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
                eva_result = str(data.get("result") or "")
                for key in ("disposable", "free", "role_account"):
                    if key in data:
                        metadata[f"eva_{key}"] = str(bool(data[key])).lower()
                reason = str(data.get("reason") or "").strip()
                if reason:
                    metadata["eva_reason"] = reason[:200]
            else:
                metadata["eva_error"] = f"HTTP {eva.status_code}"
        except Exception as exc:  # noqa: BLE001 - enrichment is best-effort
            metadata["eva_error"] = str(exc)[:120]

        kickbox_disposable = ""
        try:
            kb = client.check(kickbox_url)
            payload = _json_dict(kb) if kb.status_code == 200 else None
            if isinstance(payload, dict) and "disposable" in payload:
                kickbox_disposable = str(bool(payload["disposable"])).lower()
                metadata["kickbox_disposable"] = kickbox_disposable
        except Exception as exc:  # noqa: BLE001
            metadata["kickbox_error"] = str(exc)[:120]

        if not eva_result and not kickbox_disposable:
            return (
                Finding(
                    module=self.name, source="email-quality", target=email,
                    status="unknown", confidence="low",
                    evidence="Both reputation sources were unavailable.",
                    metadata=metadata,
                ),
            )
        title = f"Email quality: {eva_result or 'checked'}"
        if kickbox_disposable == "true":
            title += " · disposable"
        return (
            Finding(
                module=self.name, source="email-quality", target=email,
                status="candidate", url=eva_url,
                title=title,
                confidence="medium" if eva_result == "deliverable" else "low",
                evidence=(
                    f"EVA classification: {eva_result or 'n/a'}; "
                    f"Kickbox disposable: {kickbox_disposable or 'n/a'}."
                ),
                metadata=metadata,
            ),
        )
