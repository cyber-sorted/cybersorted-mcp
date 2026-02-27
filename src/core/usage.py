"""Usage tracking and tier limit enforcement.

Firestore structure:
  mcp-usage/{api_key_id}/monthly/{YYYY-MM}
    - recon_passive: int
    - recon_active: int
    - ...
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from google.cloud import firestore

from src.core.config import settings

if TYPE_CHECKING:
    pass

# Tier limits: tool_name -> max calls per month (None = unlimited)
TIER_LIMITS: dict[str, dict[str, int | None]] = {
    "free": {
        "recon_passive": 5,
    },
    "pro": {
        "recon_passive": None,
        "recon_active": None,
        "scan_web_application": 20,
        "scan_infrastructure": 10,
        "scan_api": 20,
    },
    "enterprise": {
        "recon_passive": None,
        "recon_active": None,
        "scan_web_application": None,
        "scan_infrastructure": None,
        "scan_api": None,
        "exploit_verify": None,
        "exploit_chain": None,
    },
}

# Free tier: only these tools are accessible
TIER_TOOLS: dict[str, set[str]] = {
    "free": {"recon_passive"},
    "pro": {
        "recon_passive",
        "recon_active",
        "scan_web_application",
        "scan_infrastructure",
        "scan_api",
        "generate_report",
        "generate_remediation_plan",
        "schedule_test",
        "compare_results",
    },
    "enterprise": {
        "recon_passive",
        "recon_active",
        "scan_web_application",
        "scan_infrastructure",
        "scan_api",
        "exploit_verify",
        "exploit_chain",
        "generate_report",
        "generate_remediation_plan",
        "schedule_test",
        "compare_results",
    },
}


def _get_db() -> firestore.Client:
    return firestore.Client(
        project=settings.GCP_PROJECT,
        database=settings.FIRESTORE_DATABASE,
    )


def _current_month_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


async def check_usage(api_key_id: str, tier: str, tool_name: str) -> tuple[bool, str]:
    """Check whether the API key can use the given tool.

    Returns (allowed, reason).
    """
    # Check tool access
    allowed_tools = TIER_TOOLS.get(tier, set())
    if tool_name not in allowed_tools:
        return False, f"Tool '{tool_name}' is not available on the {tier} tier."

    # Check limit
    limit = TIER_LIMITS.get(tier, {}).get(tool_name)
    if limit is None:
        return True, ""

    db = _get_db()
    month_key = _current_month_key()
    doc_ref = db.collection("mcp-usage").document(api_key_id).collection("monthly").document(
        month_key
    )
    doc = doc_ref.get()

    current_count = 0
    if doc.exists:
        data = doc.to_dict() or {}
        current_count = data.get(tool_name, 0)

    if current_count >= limit:
        return False, f"Monthly limit reached for '{tool_name}' ({limit} calls on {tier} tier)."

    return True, ""


async def record_usage(api_key_id: str, tool_name: str) -> None:
    """Increment the usage counter for a tool call."""
    db = _get_db()
    month_key = _current_month_key()
    doc_ref = db.collection("mcp-usage").document(api_key_id).collection("monthly").document(
        month_key
    )

    doc_ref.set({tool_name: firestore.Increment(1)}, merge=True)
