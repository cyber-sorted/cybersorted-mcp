"""Internal API key authentication for APP → MCP server communication.

Internal keys use the prefix ``cs_internal_`` and grant tier=internal access,
bypassing the standard MCP tier/usage limits. They are stored in the same
``mcp-api-keys`` Firestore collection but with ``tier: "internal"``.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from fastapi import Request
from google.cloud import firestore

from src.core.config import settings

logger = logging.getLogger(__name__)

INTERNAL_PREFIX = "cs_internal_"


@dataclass
class InternalAuthContext:
    """Authenticated internal caller."""

    api_key_id: str
    service: str  # e.g. "app-scanner"


class InternalAuthError(Exception):
    """Raised when internal authentication fails."""

    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


async def authenticate_internal(request: Request) -> InternalAuthContext:
    """Authenticate an internal API request.

    Expects: ``Authorization: Bearer cs_internal_xxx``

    Raises:
        InternalAuthError: If the key is missing, invalid, or not internal tier.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise InternalAuthError("Missing or invalid Authorization header")

    api_key = auth_header.removeprefix("Bearer ").strip()
    if not api_key.startswith(INTERNAL_PREFIX):
        raise InternalAuthError("Not an internal API key", status_code=403)

    # Hash and look up in Firestore
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    db = firestore.Client(
        project=settings.GCP_PROJECT,
        database=settings.FIRESTORE_DATABASE,
    )
    doc = db.collection("mcp-api-keys").document(key_hash).get()

    if not doc.exists:
        logger.warning("Internal auth failed: key not found (hash=%s...)", key_hash[:12])
        raise InternalAuthError("Invalid API key")

    data = doc.to_dict()
    if not data.get("active", False):
        raise InternalAuthError("API key is disabled")

    if data.get("tier") != "internal":
        raise InternalAuthError("Not an internal API key", status_code=403)

    return InternalAuthContext(
        api_key_id=key_hash,
        service=data.get("service", "unknown"),
    )
