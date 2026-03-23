"""ICP Scoring for pipeline companies.

Scores companies 0-100 based on ICP fit:
- Company size (SIC codes as proxy)
- Industry sector match
- Active status
- UK location
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Target SIC codes (technology, consulting, fintech)
TARGET_SIC_CODES = {
    "62011",  # Ready-made interactive leisure and entertainment software development
    "62012",  # Business and domestic software development
    "62020",  # Information technology consultancy activities
    "62090",  # Other information technology service activities
    "63110",  # Data processing, hosting and related activities
    "63120",  # Web portals
    "64191",  # Banks
    "64205",  # Activities of financial services holding companies
    "64999",  # Financial intermediation not elsewhere classified
    "70229",  # Management consultancy activities other than financial management
    "72110",  # Research and experimental development on biotechnology
    "72190",  # Other research and experimental development on natural sciences and engineering
    "86101",  # Hospital activities
    "86210",  # General medical practice activities
}

ADJACENT_SIC_CODES = {
    "61100",  # Wired telecommunications activities
    "61200",  # Wireless telecommunications activities
    "61900",  # Other telecommunications activities
    "69101",  # Solicitors
    "69102",  # Activities of patent and copyright agents
    "73110",  # Advertising agencies
    "74909",  # Other professional, scientific and technical activities
    "85310",  # General secondary education
    "85320",  # Technical and vocational secondary education
}


def score_company(company: dict) -> dict:
    """Score a company against ICP criteria.

    Returns the company dict with added `icp_score` and `icp_factors` fields.
    """
    score = 0
    factors = {}

    # Active status (20 points)
    if company.get("company_status") == "active":
        factors["status"] = {"score": 20, "reason": "Active company"}
        score += 20
    else:
        factors["status"] = {"score": 0, "reason": f"Status: {company.get('company_status')}"}

    # Industry match via SIC codes (30 points)
    sic_codes = set(company.get("sic_codes") or [])
    if sic_codes & TARGET_SIC_CODES:
        factors["industry"] = {"score": 30, "reason": "Target industry SIC code match"}
        score += 30
    elif sic_codes & ADJACENT_SIC_CODES:
        factors["industry"] = {"score": 15, "reason": "Adjacent industry SIC code"}
        score += 15
    else:
        factors["industry"] = {"score": 5, "reason": "No SIC code match"}
        score += 5

    # UK location (20 points)
    address = (company.get("address") or "").lower()
    if "england" in address or "scotland" in address or "wales" in address or "uk" in address or "united kingdom" in address:
        factors["geography"] = {"score": 20, "reason": "UK based"}
        score += 20
    else:
        factors["geography"] = {"score": 5, "reason": "Location unclear"}
        score += 5

    # Company age — established companies score higher (15 points)
    creation_date = company.get("date_of_creation")
    if creation_date:
        try:
            from datetime import datetime
            created = datetime.strptime(creation_date, "%Y-%m-%d")
            years = (datetime.now() - created).days / 365
            if years >= 3:
                factors["maturity"] = {"score": 15, "reason": f"Established ({years:.0f} years)"}
                score += 15
            elif years >= 1:
                factors["maturity"] = {"score": 10, "reason": f"Growing ({years:.1f} years)"}
                score += 10
            else:
                factors["maturity"] = {"score": 5, "reason": "New company (<1 year)"}
                score += 5
        except ValueError:
            factors["maturity"] = {"score": 5, "reason": "Unknown age"}
            score += 5

    # Has officers (15 points — indicates real operational company)
    officer_count = company.get("officer_count", 0)
    if officer_count >= 2:
        factors["officers"] = {"score": 15, "reason": f"{officer_count} officers"}
        score += 15
    elif officer_count == 1:
        factors["officers"] = {"score": 10, "reason": "1 officer"}
        score += 10
    else:
        factors["officers"] = {"score": 0, "reason": "No officer data"}

    company["icp_score"] = min(score, 100)
    company["icp_factors"] = factors

    return company


def score_batch(companies: list[dict]) -> list[dict]:
    """Score a batch of companies and sort by score descending."""
    scored = [score_company(c) for c in companies]
    scored.sort(key=lambda c: c.get("icp_score", 0), reverse=True)
    return scored
