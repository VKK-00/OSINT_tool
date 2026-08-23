"""Domain / IP recon using free public services:

* DNS-over-HTTPS (Google) — A/AAAA/MX/TXT/NS records
* crt.sh certificate transparency subdomains
* rdap.org registration data
"""
from __future__ import annotations

import asyncio
import socket

from osintkit.core import Finding, HttpClient
from osintkit.modules.base import Module, register


def _is_ip(target: str) -> bool:
    try:
        socket.inet_aton(target)
        return True
    except OSError:
        return False


@register
class NetReconModule(Module):
    name = "net"
    help = "Domain/IP recon: DoH records, crt.sh subs, RDAP whois"
    target_hint = "e.g. example.gov.ua or 8.8.8.8"

    async def run(self, target: str, http: HttpClient) -> list[Finding]:
        return await (self._ip(target, http) if _is_ip(target) else self._domain(target, http))

    async def _ip(self, ip: str, http: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        try:
            rdap = await http.get_json(f"https://rdap.org/ip/{ip}")
            net = rdap.get("name", "?")
            country = rdap.get("country", {}).get("name", "") if isinstance(rdap.get("country"), dict) else str(rdap.get("country", ""))
            orgs = []
            for ent in rdap.get("entities", []):
                roles = ent.get("roles", [])
                fn = ""
                v = ent.get("vcardArray")
                if isinstance(v, list) and len(v) > 1:
                    for item in v[1]:
                        if item and item[0] == "fn":
                            fn = item[3]
                            break
                orgs.append(f"{fn or '?'}({','.join(roles)})")
            findings.append(Finding(kind="ip", source=self.name, value=ip,
                                    confidence="high",
                                    extra={"network": net, "country": country,
                                           "entities": "; ".join(orgs[:6]),
                                           "handle": rdap.get("handle", "")}))
        except Exception as exc:
            findings.append(Finding(kind="ip", source=self.name,
                                    value=f"RDAP failed: {exc}", confidence="low"))
        return findings

    async def _domain(self, domain: str, http: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        uniq: list[str] = []

        # DNS over HTTPS
        for rtype in ("A", "MX", "TXT", "NS"):
            try:
                ans = await http.get_json(
                    f"https://dns.google/resolve?name={domain}&type={rtype}")
                vals = [a.get("data", "") for a in ans.get("Answer", [])]
                if vals:
                    findings.append(Finding(kind="dns", source=self.name,
                                            value=f"{rtype}: " + ", ".join(vals[:6]),
                                            confidence="high"))
            except Exception:
                pass

        # Certificate transparency subdomains (crt.sh is flaky — retry once)
        import asyncio as _aio
        for attempt in range(2):
            try:
                subs_ct = await http.get_json(
                    f"https://crt.sh/?q=%.{domain}&output=json")
                names = sorted({n.strip() for row in subs_ct[:400]
                                for n in row.get("name_value", "").split("\n")})
                uniq = [n for n in names if n.endswith(domain)]
                if uniq:
                    findings.append(Finding(kind="subdomains", source=self.name,
                                            value=f"{len(uniq)} unique names from CT logs",
                                            confidence="high",
                                            url=f"https://crt.sh/?q=%.{domain}",
                                            extra={"names": uniq[:100]}))
                break
            except Exception:
                if attempt == 0:
                    await _aio.sleep(2)

        # RDAP
        try:
            rdap = await http.get_json(f"https://rdap.org/domain/{domain}")
            events = {e.get("eventAction"): e.get("eventDate", "")[:10] for e in rdap.get("events", [])}
            findings.append(Finding(kind="whois", source=self.name, value=domain,
                                    confidence="high",
                                    extra={"registrar": rdap.get("registrar", ""),
                                           "registered": events.get("registration"),
                                           "expires": events.get("expiration"),
                                           "status": ",".join(rdap.get("status", [])[:4])}))
        except Exception:
            pass

        # Liveness: resolve CT subdomains via DoH
        try:
            subs = [u for u in uniq if u != domain][:25]

            async def resolve(name):
                try:
                    ans = await http.get_json(
                        "https://dns.google/resolve?name=" + name + "&type=A")
                    for a in ans.get("Answer", []):
                        if a.get("type") == 1:
                            return name, str(a.get("data"))
                except Exception:
                    pass
                return name, ""

            resolved = await asyncio.gather(*(resolve(s) for s in subs))
            live = {n: ip for n, ip in resolved if ip}
            if live:
                findings.append(Finding(
                    kind="live_hosts", source=self.name,
                    value=str(len(live)) + " of " + str(len(subs)) + " CT names resolve",
                    confidence="medium",
                    extra={"hosts": dict(list(live.items())[:25])}))
        except Exception:
            pass
        return findings
