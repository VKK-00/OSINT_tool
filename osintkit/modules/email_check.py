"""Email intelligence — passive, key-free checks.

* Gravatar existence (MD5 of address)
* XposedOrNot public breach API
* Gravatar profile (public name/avatar) when present
"""
from __future__ import annotations

import hashlib

from osintkit.core import Finding, HttpClient
from osintkit.modules.base import Module, register


@register
class EmailModule(Module):
    name = "email"
    help = "Email checks: gravatar profile, public breach exposure"
    target_hint = "e.g. someone@gmail.com"

    async def run(self, target: str, http: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        if "@" not in target:
            raise ValueError("not an email address")
        local, domain = target.rsplit("@", 1)
        md5 = hashlib.md5(target.strip().lower().encode()).hexdigest()

        # Gravatar: probe avatar existence, then fetch public profile
        status, _ = await http.head_or_get_status(f"https://www.gravatar.com/avatar/{md5}?d=404")
        if status == 200:
            findings.append(Finding(kind="email", source=self.name,
                                    value="Gravatar avatar exists", confidence="high",
                                    url=f"https://gravatar.com/{md5}"))
            try:
                prof = await http.get_json(f"https://en.gravatar.com/{md5}.json")
                entry = prof.get("entry", [{}])[0]
                findings.append(Finding(
                    kind="identity", source=self.name,
                    value=f"Gravatar profile: {entry.get('displayName','?')}",
                    confidence="high", url=entry.get("profileUrl", ""),
                    extra={"about": entry.get("aboutMe", ""),
                           "accounts": [a.get("shortname") for a in entry.get("accounts", [])]},
                ))
            except Exception:
                pass

        # Breaches via XposedOrNot (free, no key)
        try:
            xn = await http.get_json(f"https://api.xposedornot.com/v1/check-email/{target}")
            breaches = xn.get("breaches") or []
            if breaches:
                findings.append(Finding(kind="exposure", source=self.name,
                                        value=f"Breaches ({len(breaches)}): " +
                                              ", ".join(breaches[:10]),
                                        confidence="medium"))
        except Exception:
            pass

        # Domain mail hints
        findings.append(Finding(kind="lead", source=self.name,
                                value=f"Domain to pivot on: {domain}",
                                confidence="low",
                                url=f"https://crt.sh/?q=%.{domain}"))
        return findings
