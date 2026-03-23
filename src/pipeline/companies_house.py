"""Companies House API client for ICP pipeline.

Searches for UK companies, fetches officer changes and recent filings
to build the prospect pipeline.

GCP Secret: companies-house-cyber-sorted-live
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timedelta

import httpx
from google.cloud import secretmanager

from src.core.config import settings

logger = logging.getLogger(__name__)

BASE_URL = "https://api.company-information.service.gov.uk"

_api_key_cache: str | None = None


async def _get_api_key() -> str:
    """Get Companies House API key from GCP Secret Manager (cached)."""
    global _api_key_cache
    if _api_key_cache:
        return _api_key_cache

    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{settings.GCP_PROJECT}/secrets/companies-house-cyber-sorted-live/versions/latest"
    response = client.access_secret_version(request={"name": name})
    _api_key_cache = response.payload.data.decode("utf-8").strip()
    return _api_key_cache


def _auth_header(api_key: str) -> dict:
    """Build Basic auth header for Companies House API."""
    encoded = base64.b64encode(f"{api_key}:".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


async def search_companies(
    query: str,
    items_per_page: int = 20,
) -> list[dict]:
    """Search Companies House for companies by name."""
    api_key = await _get_api_key()

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BASE_URL}/search/companies",
            params={"q": query, "items_per_page": items_per_page},
            headers=_auth_header(api_key),
        )

    if response.status_code != 200:
        logger.error("Companies House search failed: %s", response.status_code)
        return []

    data = response.json()
    return [
        {
            "company_number": item.get("company_number"),
            "company_name": item.get("title"),
            "company_status": item.get("company_status"),
            "date_of_creation": item.get("date_of_creation"),
            "address": item.get("address_snippet"),
            "sic_codes": item.get("sic_codes", []),
        }
        for item in data.get("items", [])
    ]


async def get_company_profile(company_number: str) -> dict | None:
    """Get full company profile."""
    api_key = await _get_api_key()

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BASE_URL}/company/{company_number}",
            headers=_auth_header(api_key),
        )

    if response.status_code != 200:
        return None

    return response.json()


async def get_officers(company_number: str) -> list[dict]:
    """Get company officers (directors, secretaries)."""
    api_key = await _get_api_key()

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BASE_URL}/company/{company_number}/officers",
            headers=_auth_header(api_key),
        )

    if response.status_code != 200:
        return []

    return response.json().get("items", [])


async def get_recent_filings(
    company_number: str,
    days_back: int = 30,
) -> list[dict]:
    """Get recent filing history."""
    api_key = await _get_api_key()

    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BASE_URL}/company/{company_number}/filing-history",
            params={"items_per_page": 10},
            headers=_auth_header(api_key),
        )

    if response.status_code != 200:
        return []

    cutoff = datetime.now() - timedelta(days=days_back)
    filings = []

    for item in response.json().get("items", []):
        filed_date = item.get("date")
        if filed_date:
            try:
                if datetime.strptime(filed_date, "%Y-%m-%d") >= cutoff:
                    filings.append(item)
            except ValueError:
                pass

    return filings


async def import_companies(
    search_queries: list[str],
    items_per_page: int = 10,
) -> list[dict]:
    """Import companies from Companies House based on search queries.

    Default queries target ICP sectors: cybersecurity, technology consulting,
    fintech, healthtech, SaaS.
    """
    if not search_queries:
        search_queries = [
            "cybersecurity UK",
            "technology consulting UK",
            "fintech UK",
            "healthtech UK",
            "SaaS UK",
            "managed service provider UK",
        ]

    all_companies = []
    seen_numbers = set()

    for query in search_queries:
        results = await search_companies(query, items_per_page=items_per_page)
        for company in results:
            cn = company.get("company_number")
            if cn and cn not in seen_numbers and company.get("company_status") == "active":
                seen_numbers.add(cn)
                all_companies.append(company)

    logger.info("Imported %d companies from %d queries", len(all_companies), len(search_queries))
    return all_companies
