"""Domain/IP intelligence from public sources.

- Shodan InternetDB: open IP exposure snapshot (ports, hostnames, CVEs), no key;
- Wayback Machine CDX: earliest/latest snapshot of a domain = age floor, no key;
- urlScan.io search API: scan history for a domain (operator-provided free key).

Only public data is surfaced; urlScan runs only when the operator explicitly
exports URLSCAN_API_KEY.
"""
from __future__ import annotations

import json
import os
import re
import socket
from dataclasses import dataclass
from urllib.parse import quote

from ..engine import Finding, RunConfig, ScanTarget
from ..http_client import HttpClient

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
CDX_URL = (
    "https://web.archive.org/cdx/search/cdx?url={host}&output=json"
    "&fl=timestamp,original&collapse=urlkey{limit}"
)
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10"


def _json_object(result) -> dict | list | None:
    try:
        payload = json.loads(result.body_text)
    except (json.JSONDecodeError, TypeError):
        return None
    return payload


def _resolve_ipv4(domain: str) -> str | None:
    try:
        records = socket.getaddrinfo(domain, None, socket.AF_INET)
    except (socket.gaierror, OSError):
        return None
    for record in records:
        address = record[4][0] if record[4] else None
        if address:
            return str(address)
    return None


@dataclass(frozen=True)
class InternetDbModule:
    name: str = "internetdb-ip"
    supported_targets: tuple[str, ...] = ("domain",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        domain = target.value.strip()
        host = _host_of(domain)
        if not config.live:
            return (
                Finding(
                    module=self.name, source="internetdb", target=target.value,
                    status="planned",
                    url="https://internetdb.shodan.io/",
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to resolve the domain and query InternetDB.",
                    metadata={"queried_host": host},
                ),
            )
        ip = _resolve_ipv4(host)
        if not ip:
            return (
                Finding(
                    module=self.name, source="internetdb", target=target.value,
                    status="not_found", confidence="medium",
                    evidence=f"Could not resolve '{host}' to an IPv4 address.",
                    metadata={"queried_host": host},
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        result = client.check(INTERNETDB_URL.format(ip=ip))
        payload = _json_object(result) if result.status_code == 200 else None
        if result.status_code == 404:
            return (
                Finding(
                    module=self.name, source="internetdb", target=target.value,
                    status="not_found", url=result.final_url or INTERNETDB_URL.format(ip=ip),
                    http_status=404, confidence="high",
                    evidence=f"InternetDB has no open-port snapshot for {ip}.",
                    metadata={"queried_host": host, "ip": ip},
                ),
            )
        if not isinstance(payload, dict):
            return (
                Finding(
                    module=self.name, source="internetdb", target=target.value,
                    status="unknown", http_status=result.status_code,
                    confidence="low",
                    evidence=result.error or f"HTTP {result.status_code} from InternetDB.",
                    metadata={"queried_host": host, "ip": ip},
                ),
            )
        ports = [str(port) for port in (payload.get("ports") or [])][:20]
        vulns = [str(vuln) for vuln in (payload.get("vulns") or [])][:15]
        hostnames = [str(name) for name in (payload.get("hostnames") or [])][:10]
        metadata = {
            "queried_host": host,
            "ip": str(payload.get("ip") or ip),
            "port_count": str(len(payload.get("ports") or [])),
            "ports": ", ".join(ports),
            "hostnames": ", ".join(hostnames),
            "cpe_count": str(len(payload.get("cpes") or [])),
            "vulnerability_count": str(len(payload.get("vulns") or [])),
            "vulnerabilities": ", ".join(vulns),
        }
        return (
            Finding(
                module=self.name, source="internetdb", target=target.value,
                status="candidate",
                url=INTERNETDB_URL.format(ip=ip),
                title=f"{ip}: {len(ports)} open ports, {len(vulns)} known CVEs",
                http_status=200, confidence="medium",
                evidence="Public InternetDB exposure snapshot for the resolved IP.",
                metadata=metadata,
            ),
        )


@dataclass(frozen=True)
class WaybackCdxModule:
    name: str = "wayback-cdx"
    supported_targets: tuple[str, ...] = ("domain", "url")

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        host = _host_of(target.value)
        cdx_base = CDX_URL.format(host=quote(host, safe=""), limit="&limit=1")
        if not config.live:
            return (
                Finding(
                    module=self.name, source="cdx-timeline", target=target.value,
                    status="planned", url=cdx_base.replace("&limit=1", ""),
                    confidence="not_checked",
                    evidence="Dry run only. Pass --live to fetch the Wayback CDX timeline bounds.",
                    metadata={"queried_host": host},
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        earliest = self._edge(client, cdx_base, last=False)
        latest = self._edge(client, cdx_base, last=True)
        if earliest is None and latest is None:
            return (
                Finding(
                    module=self.name, source="cdx-timeline", target=target.value,
                    status="not_found", confidence="medium",
                    evidence=f"No Wayback Machine snapshots found for '{host}'.",
                    metadata={"queried_host": host},
                ),
            )
        metadata = {
            "queried_host": host,
            "earliest_snapshot": earliest or "",
            "latest_snapshot": latest or "",
        }
        if earliest:
            year = int(earliest[:4])
            current_year = int((latest or earliest)[:4])
            metadata["observed_age_years"] = str(current_year - year + 1)
        return (
            Finding(
                module=self.name, source="cdx-timeline", target=target.value,
                status="candidate", confidence="medium",
                title=(f"Archived since {earliest[:4]}" if earliest else f"Snapshots up to {latest[:4]}"),
                url=f"https://web.archive.org/web/*/{host}",
                evidence=(
                    f"Earliest Wayback snapshot {earliest}; latest {latest}. "
                    "Snapshot date is a lower bound for how long the site existed."
                ),
                metadata=metadata,
            ),
        )

    def _edge(self, client: HttpClient, base_url: str, *, last: bool) -> str | None:
        url = base_url.replace("&limit=1", "&limit=-1") if last else base_url
        result = client.check(url)
        payload = _json_object(result) if result.status_code == 200 else None
        if not isinstance(payload, list) or len(payload) < 2:
            return None
        first_row = payload[1]
        if isinstance(first_row, list) and first_row:
            timestamp = str(first_row[0])
            return timestamp if len(timestamp) >= 4 else None
        return None


@dataclass(frozen=True)
class UrlscanSearchModule:
    name: str = "urlscan-search"
    supported_targets: tuple[str, ...] = ("domain", "url")

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        host = _host_of(target.value)
        api_key = os.environ.get("URLSCAN_API_KEY", "").strip()
        url = URLSCAN_SEARCH_URL.format(domain=quote(host, safe=""))
        if not api_key:
            return (
                Finding(
                    module=self.name, source="urlscan-api", target=target.value,
                    status="skipped", confidence="high",
                    evidence=(
                        "URLSCAN_API_KEY is not set; get a free key at "
                        "https://urlscan.io/user/profile/ and export it to enable scan-history search."
                    ),
                    metadata={"queried_host": host},
                ),
            )
        if not config.live:
            return (
                Finding(
                    module=self.name, source="urlscan-api", target=target.value,
                    status="planned", url=url, confidence="not_checked",
                    evidence="Dry run only. Pass --live to search public urlScan history.",
                    metadata={"queried_host": host},
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        result = client.check(url, headers={"API-Key": api_key})
        payload = _json_object(result) if result.status_code == 200 else None
        if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
            return (
                Finding(
                    module=self.name, source="urlscan-api", target=target.value,
                    status="unknown", http_status=result.status_code,
                    confidence="low",
                    evidence=result.error or f"HTTP {result.status_code} from urlScan.",
                    metadata={"queried_host": host},
                ),
            )
        results = payload["results"]
        sample_rows = []
        for item in results[:5]:
            page = item.get("page") if isinstance(item.get("page"), dict) else {}
            task = item.get("task") if isinstance(item.get("task"), dict) else {}
            sample_rows.append(
                " | ".join(filter(None, (
                    str(page.get("url") or "")[:100],
                    str(page.get("ip") or ""),
                    str(task.get("time") or "")[:10],
                )))
            )
        return (
            Finding(
                module=self.name, source="urlscan-api", target=target.value,
                status="candidate", url=url, http_status=200,
                confidence="medium",
                title=f"urlScan history: {payload.get('total', len(results))} scans for {host}",
                evidence=f"Public urlScan scan history for domain '{host}'.",
                metadata={
                    "queried_host": host,
                    "total_scans": str(payload.get("total", len(results))),
                    "recent_scans": " || ".join(sample_rows),
                },
            ),
        )


def _host_of(value: str) -> str:
    raw = value.strip()
    if "://" in raw:
        raw = raw.split("://", 1)[-1]
    raw = raw.split("/", 1)[0]
    raw = raw.rpartition("@")[2] or raw
    host = raw.partition(":")[0].lower()
    return host[4:] if host.startswith("www.") and host.count(".") > 1 else host


HACKERTARGET_HOSTSEARCH_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"


@dataclass(frozen=True)
class PassiveDnsModule:
    """Keyless passive hostname/IP lookup via the HackerTarget host search.

    The free endpoint is rate limited per source IP; quota exhaustion is
    reported as an ``unknown`` observation instead of a fake negative.
    """

    name: str = "hackertarget-hostsearch"
    supported_targets: tuple[str, ...] = ("domain",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        host = _host_of(target.value)
        url = HACKERTARGET_HOSTSEARCH_URL.format(domain=quote(host, safe=""))
        if not config.live:
            return (
                Finding(
                    module=self.name, source="passive-dns", target=target.value,
                    status="planned", url=url, confidence="not_checked",
                    evidence="Dry run only. Pass --live to query the keyless passive-hostname API.",
                    metadata={"queried_host": host},
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        result = client.check(url)
        text = (result.body_text or "").strip()
        if result.status_code != 200:
            return (
                Finding(
                    module=self.name, source="passive-dns", target=target.value,
                    status="unknown", http_status=result.status_code,
                    confidence="low",
                    evidence=result.error or f"HTTP {result.status_code} from HackerTarget.",
                    metadata={"queried_host": host},
                ),
            )
        lowered = text.lower()
        if not text or "error" in lowered[:80] or "count exceeded" in lowered[:120]:
            return (
                Finding(
                    module=self.name, source="passive-dns", target=target.value,
                    status="unknown", http_status=result.status_code,
                    confidence="low",
                    evidence="Passive-DNS quota exhausted or request rejected; retry later.",
                    metadata={"queried_host": host},
                ),
            )
        pairs = parse_hackertarget_hostsearch(text)
        if not pairs:
            return (
                Finding(
                    module=self.name, source="passive-dns", target=target.value,
                    status="not_found", http_status=200,
                    confidence="medium",
                    evidence=f"No passive-DNS hostnames found for '{host}'.",
                    metadata={"queried_host": host},
                ),
            )
        hosts = [hostname for hostname, _ip in pairs]
        ips = sorted({ip for _hostname, ip in pairs})
        return (
            Finding(
                module=self.name, source="passive-dns", target=target.value,
                status="candidate", url=url, http_status=200,
                confidence="low",
                title=f"Passive DNS: {len(pairs)} hostnames on {len(ips)} IPs",
                evidence="Keyless passive-hostname lookup (HackerTarget free tier).",
                metadata={
                    "queried_host": host,
                    "host_count": str(len(pairs)),
                    "subdomains": ", ".join(hosts[:20]),
                    "ip_count": str(len(ips)),
                    "ips": ", ".join(ips[:15]),
                },
            ),
        )


def parse_hackertarget_hostsearch(text: str) -> tuple[tuple[str, str], ...]:
    """Parse 'host,ip' lines; keep only entries under the queried domain."""
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if "," not in line:
            continue
        hostname, _, ip = line.partition(",")
        hostname = hostname.strip().lower()
        ip = ip.strip()
        if not hostname or "." not in hostname or hostname in seen:
            continue
        seen.add(hostname)
        pairs.append((hostname, ip))
    return tuple(pairs)


IPAPI_URL = "http://ip-api.com/json/{ip}"
IPAPI_FIELDS = (
    "status,message,country,countryCode,regionName,city,zip,lat,lon,"
    "timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
)


@dataclass(frozen=True)
class IpGeoModule:
    """Keyless IP geolocation + network ownership via ip-api.com (45 req/min)."""

    name: str = "ip-api-geo"
    supported_targets: tuple[str, ...] = ("domain", "url")

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        host = _host_of(target.value)
        if not config.live:
            return (
                Finding(
                    module=self.name, source="ip-api", target=target.value,
                    status="planned", confidence="not_checked",
                    evidence="Dry run only. Pass --live to resolve the host and query ip-api.",
                    metadata={"queried_host": host},
                ),
            )
        ip = _resolve_ipv4(host)
        if not ip:
            return (
                Finding(
                    module=self.name, source="ip-api", target=target.value,
                    status="not_found", confidence="medium",
                    evidence=f"Could not resolve '{host}' to an IPv4 address.",
                    metadata={"queried_host": host},
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        result = client.check(IPAPI_URL.format(ip=ip))
        payload = _json_object(result) if result.status_code == 200 else None
        if not isinstance(payload, dict) or payload.get("status") != "success":
            message = str((payload or {}).get("message") or result.error
                          or f"HTTP {result.status_code}")
            return (
                Finding(
                    module=self.name, source="ip-api", target=target.value,
                    status="unknown", http_status=result.status_code,
                    confidence="low", evidence=message,
                    metadata={"queried_host": host, "ip": ip},
                ),
            )
        metadata = {
            "queried_host": host,
            "ip": str(payload.get("query") or ip),
            "country": str(payload.get("country") or ""),
            "country_code": str(payload.get("countryCode") or ""),
            "region": str(payload.get("regionName") or ""),
            "city": str(payload.get("city") or ""),
            "lat": str(payload.get("lat") or ""),
            "lon": str(payload.get("lon") or ""),
            "timezone": str(payload.get("timezone") or ""),
            "isp": str(payload.get("isp") or ""),
            "org": str(payload.get("org") or ""),
            "as": str(payload.get("as") or ""),
            "reverse_dns": str(payload.get("reverse") or ""),
            "is_mobile": "yes" if payload.get("mobile") else "no",
            "is_proxy": "yes" if payload.get("proxy") else "no",
            "is_hosting": "yes" if payload.get("hosting") else "no",
        }
        metadata = {key: value for key, value in metadata.items() if value}
        location_bits = ", ".join(filter(None, (
            payload.get("city"), payload.get("regionName"), payload.get("country"))))
        return (
            Finding(
                module=self.name, source="ip-api", target=target.value,
                status="candidate", url=IPAPI_URL.format(ip=ip),
                title=f"{ip} — {location_bits or 'unknown location'}",
                http_status=200, confidence="medium",
                evidence="Keyless ip-api.com network ownership and geolocation lookup.",
                metadata=metadata,
            ),
        )


DOMAINSDB_SEARCH_URL = "https://api.domainsdb.info/v1/domains/search?domain={query}"


@dataclass(frozen=True)
class DomainsdbSearchModule:
    """Registered-domain search by name word (brand/typo pivots), free API."""

    name: str = "domainsdb-search"
    supported_targets: tuple[str, ...] = ("domain", "company")

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        word = re.sub(r"[^A-Za-z0-9-]", "", target.value.strip()).lower()
        if len(word) < 3:
            return (
                Finding(
                    module=self.name, source="normalizer", target=target.value,
                    status="invalid", confidence="high",
                    evidence="Need at least 3 latin/digit characters for a domain search.",
                ),
            )
        url = DOMAINSDB_SEARCH_URL.format(query=quote(word))
        if not config.live:
            return (
                Finding(
                    module=self.name, source="domainsdb", target=target.value,
                    status="planned", url=url, confidence="not_checked",
                    evidence="Dry run only. Pass --live to search registered domains.",
                    metadata={"search_word": word},
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        result = client.check(url)
        payload = _json_object(result) if result.status_code == 200 else None
        domains = payload.get("domains") if isinstance(payload, dict) else None
        if not isinstance(domains, list):
            return (
                Finding(
                    module=self.name, source="domainsdb", target=target.value,
                    status="unknown", http_status=result.status_code,
                    confidence="low",
                    evidence=(
                        result.error
                        or f"HTTP {result.status_code} from DomainsDB (free tier may rate-limit)."
                    ),
                    metadata={"search_word": word},
                ),
            )
        names = []
        for item in domains[:15]:
            if isinstance(item, dict) and item.get("domain"):
                names.append(str(item["domain"]))
        total = str(payload.get("total") or len(domains))
        return (
            Finding(
                module=self.name, source="domainsdb", target=target.value,
                status="candidate", url=url, http_status=200,
                confidence="low",
                title=f"DomainsDB: {total} registered domains matching '{word}'",
                evidence="Free registered-domain search; useful for brand and typo pivots.",
                metadata={
                    "search_word": word,
                    "total": total,
                    "sample_domains": ", ".join(names),
                },
            ),
        )


OTX_PASSIVE_DNS_URL = (
    "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns/page?page=1"
)


@dataclass(frozen=True)
class OtxPassiveDnsModule:
    """AlienVault OTX passive DNS (free API key, X-OTX-API-KEY header)."""

    name: str = "otx-passive-dns"
    supported_targets: tuple[str, ...] = ("domain",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        host = _host_of(target.value)
        url = OTX_PASSIVE_DNS_URL.format(domain=quote(host, safe=""))
        api_key = os.environ.get("OTX_API_KEY", "").strip()
        if not config.live:
            return (
                Finding(
                    module=self.name, source="otx-passive-dns", target=target.value,
                    status="planned", url=url, confidence="not_checked",
                    evidence=(
                        "Dry run only. Pass --live with OTX_API_KEY to query the "
                        "OTX passive-DNS history."
                    ),
                    metadata={"queried_host": host},
                ),
            )
        if not api_key:
            return (
                Finding(
                    module=self.name, source="otx-passive-dns", target=target.value,
                    status="skipped", confidence="high",
                    evidence=(
                        "OTX_API_KEY is not set; register free at "
                        "https://otx.alienvault.com to enable passive-DNS history."
                    ),
                    metadata={"queried_host": host},
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        result = client.check(url, headers={"X-OTX-API-KEY": api_key})
        payload = _json_object(result) if result.status_code == 200 else None
        records = payload.get("passive_dns") if isinstance(payload, dict) else None
        if not isinstance(records, list):
            return (
                Finding(
                    module=self.name, source="otx-passive-dns", target=target.value,
                    status="unknown", http_status=result.status_code,
                    confidence="low",
                    evidence=result.error or f"HTTP {result.status_code} from OTX.",
                    metadata={"queried_host": host},
                ),
            )
        pairs: list[tuple[str, str, str]] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            hostname = str(record.get("hostname") or "").strip().lower()
            address = str(record.get("address") or "").strip()
            last_seen = str(record.get("last") or "")[:10]
            if hostname:
                pairs.append((hostname, address, last_seen))
        if not pairs:
            return (
                Finding(
                    module=self.name, source="otx-passive-dns", target=target.value,
                    status="not_found", http_status=200, confidence="medium",
                    evidence=f"No OTX passive-DNS records found for '{host}'.",
                    metadata={"queried_host": host},
                ),
            )
        hosts = [h for h, _a, _t in pairs]
        ips = sorted({a for _h, a, _t in pairs if a})
        latest = max((t for _h, _a, t in pairs), default="")
        return (
            Finding(
                module=self.name, source="otx-passive-dns", target=target.value,
                status="candidate", url=url, http_status=200,
                confidence="medium",
                title=f"OTX passive DNS: {len(pairs)} records, latest {latest}",
                evidence="Historic hostname-to-IP observations from AlienVault OTX.",
                metadata={
                    "queried_host": host,
                    "record_count": str(len(pairs)),
                    "subdomains": ", ".join(dict.fromkeys(hosts))[:400],
                    "ips": ", ".join(ips[:15]),
                    "latest_seen": latest,
                },
            ),
        )

OTX_GENERAL_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"


@dataclass(frozen=True)
class OtxReputationModule:
    """AlienVault OTX community reputation: pulses tagging a domain."""

    name: str = "otx-reputation"
    supported_targets: tuple[str, ...] = ("domain",)

    def scan(self, target: ScanTarget, config: RunConfig) -> tuple[Finding, ...]:
        host = _host_of(target.value)
        url = OTX_GENERAL_URL.format(domain=quote(host, safe=""))
        api_key = os.environ.get("OTX_API_KEY", "").strip()
        if not config.live:
            return (
                Finding(
                    module=self.name, source="otx-general", target=target.value,
                    status="planned", url=url, confidence="not_checked",
                    evidence="Dry run only. Pass --live with OTX_API_KEY to query community reputation.",
                    metadata={"queried_host": host},
                ),
            )
        if not api_key:
            return (
                Finding(
                    module=self.name, source="otx-general", target=target.value,
                    status="skipped", confidence="high",
                    evidence="OTX_API_KEY is not set; free registration at https://otx.alienvault.com.",
                    metadata={"queried_host": host},
                ),
            )
        client = HttpClient(timeout=config.timeout, user_agent=config.user_agent,
                            retries=config.http_retries, backoff_seconds=config.http_backoff)
        result = client.check(url, headers={"X-OTX-API-KEY": api_key})
        payload = _json_object(result) if result.status_code == 200 else None
        pulse_info = payload.get("pulse_info") if isinstance(payload, dict) else None
        pulses = pulse_info.get("pulses") if isinstance(pulse_info, dict) else None
        if not isinstance(pulses, list):
            return (
                Finding(
                    module=self.name, source="otx-general", target=target.value,
                    status="unknown", http_status=result.status_code,
                    confidence="low",
                    evidence=result.error or f"HTTP {result.status_code} from OTX.",
                    metadata={"queried_host": host},
                ),
            )
        pulse_count = int(pulse_info.get("count") or len(pulses))
        if not pulses:
            return (
                Finding(
                    module=self.name, source="otx-general", target=target.value,
                    status="not_found", http_status=200, confidence="medium",
                    evidence=f"No OTX community pulses reference '{host}'.",
                    metadata={"queried_host": host},
                ),
            )
        names = [str(p.get("name") or "")[:80] for p in pulses if isinstance(p, dict)]
        tags = sorted({
            tag
            for p in pulses if isinstance(p, dict)
            for tag in (p.get("tags") or [])
            if isinstance(tag, str)
        })
        adversaries = sorted({
            str(p.get("adversary") or "")
            for p in pulses if isinstance(p, dict) and p.get("adversary")
        })
        metadata = {
            "queried_host": host,
            "pulse_count": str(pulse_count),
            "pulse_names": ", ".join(names)[:400],
            "tags": ", ".join(tags)[:200],
        }
        if adversaries:
            metadata["adversaries"] = ", ".join(adversaries)[:150]
        return (
            Finding(
                module=self.name, source="otx-general", target=target.value,
                status="candidate", url=url, http_status=200,
                title=f"OTX reputation: {pulse_count} community pulse(s)",
                confidence="medium" if pulse_count < 5 else "high",
                evidence=(
                    "Community threat-intel pulses reference this domain - "
                    "review pulse names before treating as malicious."
                ),
                metadata=metadata,
            ),
        )
