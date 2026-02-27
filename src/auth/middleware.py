"""API key authentication middleware.

Flow:
  1. Extract Bearer token from Authorization header (cs_live_xxx or cs_test_xxx)
  2. Hash the key and look up in Firestore mcp-api-keys/{key_hash}
  3. Validate Stripe subscription is active
  4. Return tier (free/pro/enterprise) and usage limits
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import stripe
from google.cloud import firestore

from src.core.config import settings


class AuthError(Exception):
    """Authentication or authorisation error."""

    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


@dataclass
class AuthContext:
    """Authenticated request context."""

    api_key_id: str
    tier: str  # free, pro, enterprise
    stripe_customer_id: str | None
    stripe_subscription_id: str | None
    domains: list[str]  # authorised target domains
    max_domains: int


def _hash_key(api_key: str) -> str:
    """SHA-256 hash of the API key for Firestore lookup."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def _get_db() -> firestore.Client:
    return firestore.Client(
        project=settings.GCP_PROJECT,
        database=settings.FIRESTORE_DATABASE,
    )


async def authenticate_request(authorization: str | None) -> AuthContext:
    """Authenticate an API key and return the auth context.

    Args:
        authorization: The Authorization header value (Bearer cs_live_xxx).

    Returns:
        AuthContext with tier, domains, and limits.

    Raises:
        AuthError: If the key is missing, invalid, or subscription is inactive.
    """
    if not authorization:
        raise AuthError("Missing Authorization header. Use: Bearer cs_live_xxx")

    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise AuthError("Invalid Authorization format. Use: Bearer cs_live_xxx")

    api_key = parts[1].strip()
    if not api_key.startswith(("cs_live_", "cs_test_")):
        raise AuthError("Invalid API key format. Keys start with cs_live_ or cs_test_")

    # Look up key in Firestore
    key_hash = _hash_key(api_key)
    db = _get_db()
    doc = db.collection("mcp-api-keys").document(key_hash).get()

    if not doc.exists:
        raise AuthError("Invalid API key.")

    data = doc.to_dict()
    if not data or not data.get("active", False):
        raise AuthError("API key is inactive.")

    tier = data.get("tier", "free")
    stripe_subscription_id = data.get("stripe_subscription_id")

    # Validate Stripe subscription for paid tiers
    if tier in ("pro", "enterprise") and stripe_subscription_id:
        if settings.STRIPE_SECRET_KEY:
            stripe.api_key = settings.STRIPE_SECRET_KEY
            try:
                subscription = stripe.Subscription.retrieve(stripe_subscription_id)
                if subscription.status not in ("active", "trialing"):
                    raise AuthError(
                        "Stripe subscription is not active. "
                        f"Current status: {subscription.status}",
                        status_code=403,
                    )
            except stripe.StripeError as e:
                raise AuthError(f"Stripe validation failed: {e}", status_code=500)

    # Domain limits by tier
    max_domains = {"free": 1, "pro": 5, "enterprise": 999}

    return AuthContext(
        api_key_id=key_hash,
        tier=tier,
        stripe_customer_id=data.get("stripe_customer_id"),
        stripe_subscription_id=stripe_subscription_id,
        domains=data.get("domains", []),
        max_domains=max_domains.get(tier, 1),
    )
