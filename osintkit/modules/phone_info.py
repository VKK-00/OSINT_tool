"""Phone number intelligence.

Offline-first: uses the bundled phonenumbers metadata — country, number type,
geographic description and carrier name. This covers RU DEF-codes and UA
operator prefixes without any external API.
"""
from __future__ import annotations

import phonenumbers
from phonenumbers import carrier, geocoder
from phonenumbers import timezone as pn_tz

from osintkit.core import Finding, HttpClient
from osintkit.modules.base import Module, register


@register
class PhoneModule(Module):
    name = "phone"
    help = "Parse phone number: country, region, carrier, timezone"
    target_hint = "E.164 or local format, e.g. +380501234567"

    def accepts(self, target: str) -> bool:
        try:
            num = phonenumbers.parse(target.strip(), None)
        except Exception:
            return False
        return phonenumbers.is_valid_number(num)

    async def run(self, target: str, http: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        num = phonenumbers.parse(target, None)
        if not phonenumbers.is_valid_number(num):
            return [Finding(kind="phone", source=self.name,
                            value="INVALID number", confidence="high")]
        e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        ntype = phonenumbers.number_type(num)
        desc = geocoder.description_for_number(num, "en") or "unknown region"
        op = carrier.name_for_number(num, "en") or "unknown carrier"
        tz = ", ".join(sorted(pn_tz.time_zones_for_number(num))) or "-"

        findings.append(Finding(kind="phone", source=self.name,
                                value=e164, confidence="high",
                                extra={
                                    "formatted": intl,
                                    "country": phonenumbers.region_code_for_number(num),
                                    "region": desc,
                                    "carrier": op,
                                    "type": {
                                        0: "FIXED_LINE", 1: "MOBILE",
                                        2: "FIXED_OR_MOBILE", 3: "TOLL_FREE",
                                        4: "PREMIUM_RATE", 5: "SHARED_COST",
                                        6: "VOIP", 7: "PERSONAL",
                                        8: "PAGER", 9: "UAN", 10: "VOICEMAIL",
                                    }.get(int(ntype), str(ntype)),
                                    "timezones": tz,
                                }))

        # Free public lookups that work without keys
        numcheck = f"https://html.duckduckgo.com/html/?q=%22{e164}%22"
        findings.append(Finding(kind="lead", source=self.name,
                                value="Manual search link (paste into browser)",
                                confidence="low", url=numcheck))
        return findings
