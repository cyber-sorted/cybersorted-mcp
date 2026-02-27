"""Passive reconnaissance tool.

Gathers information about a target domain using only public data sources.
No packets are sent to the target — all data comes from DNS resolvers and
public APIs (crt.sh, RDAP).

Data sources:
  - DNS records: dnspython (A, AAAA, MX, TXT, CNAME, NS, SOA)
  - Subdomains: Certificate Transparency via crt.sh API (httpx)
  - WHOIS: RDAP lookup via httpx
  - Technologies: HTTP response header analysis (httpx)
  - Certificates: CT log query results from crt.sh
"""

from __future__ import annotations

import logging
from typing import Any

import dns.resolver
import httpx

logger = logging.getLogger(__name__)

# DNS record types to query
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA"]

# Headers that reveal technology stack
TECH_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
    "x-drupal-cache",
    "x-varnish",
    "x-cache",
    "via",
    "x-cdn",
    "x-framework",
]


async def recon_passive(target: str, depth: str = "standard") -> dict[str, Any]:
    """Run passive reconnaissance against a target domain.

    Args:
        target: Domain to investigate (e.g. "example.com").
        depth: "standard" for quick scan, "deep" for thorough enumeration.

    Returns:
        Structured results with dns_records, domains, whois, technologies,
        and certificates.
    """
    target = target.strip().lower()

    # Remove protocol prefix if provided
    if target.startswith(("http://", "https://")):
        target = target.split("://", 1)[1].split("/", 0)[0]

    results: dict[str, Any] = {
        "target": target,
        "depth": depth,
        "dns_records": [],
        "domains": [],
        "whois": {},
        "technologies": [],
        "certificates": [],
    }

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        # Run all lookups
        results["dns_records"] = await _lookup_dns(target)
        results["domains"] = await _enumerate_subdomains(client, target, depth)
        results["whois"] = await _lookup_rdap(client, target)
        results["technologies"] = await _detect_technologies(client, target)
        results["certificates"] = await _query_ct_logs(client, target)

    return results


async def _lookup_dns(target: str) -> list[dict[str, Any]]:
    """Query DNS records for the target domain."""
    records: list[dict[str, Any]] = []
    resolver = dns.resolver.Resolver()

    for record_type in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(target, record_type)
            for rdata in answers:
                records.append({
                    "type": record_type,
                    "value": str(rdata),
                    "ttl": answers.ttl,
                })
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
            dns.name.EmptyLabel,
        ):
            continue
        except Exception as e:
            logger.debug("DNS lookup failed for %s %s: %s", target, record_type, e)
            continue

    return records


async def _enumerate_subdomains(
    client: httpx.AsyncClient,
    target: str,
    depth: str,
) -> list[str]:
    """Enumerate subdomains via Certificate Transparency logs (crt.sh)."""
    subdomains: set[str] = set()

    try:
        resp = await client.get(
            "https://crt.sh/",
            params={"q": f"%.{target}", "output": "json"},
        )
        if resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name.endswith(f".{target}") or name == target:
                        # Skip wildcard entries
                        if not name.startswith("*"):
                            subdomains.add(name)
    except Exception as e:
        logger.warning("crt.sh lookup failed for %s: %s", target, e)

    return sorted(subdomains)


async def _lookup_rdap(client: httpx.AsyncClient, target: str) -> dict[str, Any]:
    """Look up WHOIS information via RDAP."""
    whois_data: dict[str, Any] = {}

    try:
        resp = await client.get(f"https://rdap.org/domain/{target}")
        if resp.status_code == 200:
            data = resp.json()
            whois_data["name"] = data.get("ldhName", "")
            whois_data["status"] = data.get("status", [])
            whois_data["nameservers"] = [
                ns.get("ldhName", "") for ns in data.get("nameservers", [])
            ]

            # Extract registrar and dates from events
            events = data.get("events", [])
            for event in events:
                action = event.get("eventAction", "")
                date = event.get("eventDate", "")
                if action == "registration":
                    whois_data["registered"] = date
                elif action == "expiration":
                    whois_data["expires"] = date
                elif action == "last changed":
                    whois_data["updated"] = date

            # Extract registrar from entities
            entities = data.get("entities", [])
            for entity in entities:
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [None, []])
                    if len(vcard) > 1:
                        for field in vcard[1]:
                            if field[0] == "fn":
                                whois_data["registrar"] = field[3]
                                break
    except Exception as e:
        logger.warning("RDAP lookup failed for %s: %s", target, e)

    return whois_data


async def _detect_technologies(
    client: httpx.AsyncClient,
    target: str,
) -> list[dict[str, str]]:
    """Detect technologies from HTTP response headers."""
    technologies: list[dict[str, str]] = []

    for scheme in ["https", "http"]:
        try:
            resp = await client.get(f"{scheme}://{target}", follow_redirects=True)
            headers = resp.headers

            for header_name in TECH_HEADERS:
                value = headers.get(header_name)
                if value:
                    technologies.append({
                        "source": f"header:{header_name}",
                        "value": value,
                    })

            # Check for common meta patterns in response
            content_type = headers.get("content-type", "")
            if content_type:
                technologies.append({
                    "source": "header:content-type",
                    "value": content_type,
                })

            # Only need one successful scheme
            break
        except Exception as e:
            logger.debug("Technology detection failed for %s://%s: %s", scheme, target, e)
            continue

    return technologies


async def _query_ct_logs(
    client: httpx.AsyncClient,
    target: str,
) -> list[dict[str, Any]]:
    """Query Certificate Transparency logs for certificate information."""
    certificates: list[dict[str, Any]] = []

    try:
        resp = await client.get(
            "https://crt.sh/",
            params={"q": target, "output": "json"},
        )
        if resp.status_code == 200:
            entries = resp.json()
            seen_serials: set[str] = set()

            for entry in entries[:50]:  # Limit to 50 most recent
                serial = entry.get("serial_number", "")
                if serial in seen_serials:
                    continue
                seen_serials.add(serial)

                certificates.append({
                    "issuer": entry.get("issuer_name", ""),
                    "common_name": entry.get("common_name", ""),
                    "name_value": entry.get("name_value", ""),
                    "not_before": entry.get("not_before", ""),
                    "not_after": entry.get("not_after", ""),
                    "serial_number": serial,
                })
    except Exception as e:
        logger.warning("CT log query failed for %s: %s", target, e)

    return certificates
