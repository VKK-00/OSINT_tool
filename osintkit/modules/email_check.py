"""Email intelligence — passive, key-free checks.

* Gravatar existence + public profile
* XposedOrNot public breach API
* Domain MX validation (does the mailbox domain even accept mail?)
* Disposable/temp-mail domain detection
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

    def accepts(self, target: str) -> bool:
        if "@" not in target:
            return False
        domain = target.rsplit("@", 1)[-1]
        return "." in domain and len(domain) > 3

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

        # Domain mail validation + disposable detection
        DISPOSABLE = {
            "mailinator.com", "10minutemail.com", "guerrillamail.com",
            "guerrillamail.net", "sharklasers.com", "grr.la", "yopmail.com",
            "tempmail.com", "temp-mail.org", "throwawaymail.com",
            "dispostable.com", "trashmail.com", "getnada.com", "nada.email",
            "maildrop.cc", "fakeinbox.com", "mintemail.com", "tempinbox.com",
            "mytemp.email", "emailondeck.com", "mailnesia.com",
            "spamgourmet.com", "discard.email", "tempmailo.com",
            "moakt.com", "mohmal.com", "email-temp.com",
        }
        dlow = domain.lower().strip()
        if dlow in DISPOSABLE:
            findings.append(Finding(
                kind="email", source=self.name,
                value=f"DISPOSABLE email domain ({dlow}) — likely throwaway",
                confidence="high"))
        try:
            mx = await http.get_json(
                f"https://dns.google/resolve?name={domain}&type=MX")
            mxvals = [a.get("data", "") for a in mx.get("Answer", [])]
            if mxvals:
                findings.append(Finding(
                    kind="email", source=self.name,
                    value="Domain accepts mail: " + ", ".join(
                        v.split(" ")[-1].rstrip(".") for v in mxvals[:4]),
                    confidence="medium",
                    extra={"mx": [v for v in mxvals[:6]]}))
            else:
                findings.append(Finding(
                    kind="email", source=self.name,
                    value="Domain has NO MX record — address cannot receive mail",
                    confidence="medium"))
        except Exception:
            pass

        # Domain pivot
        findings.append(Finding(kind="lead", source=self.name,
                                value=f"Domain to pivot on: {domain}",
                                confidence="low",
                                url=f"https://crt.sh/?q=%.{domain}"))
        return findings
