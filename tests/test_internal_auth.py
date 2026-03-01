"""Tests for internal API key authentication."""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from src.api.internal_auth import (
    InternalAuthContext,
    InternalAuthError,
    authenticate_internal,
)


def _make_request(auth_header: str | None = None) -> MagicMock:
    """Create a mock FastAPI Request with optional auth header."""
    request = MagicMock()
    request.headers = {}
    if auth_header:
        request.headers["Authorization"] = auth_header
    return request


def _mock_firestore_doc(exists: bool = True, data: dict | None = None):
    """Create a mock Firestore document."""
    mock_db = MagicMock()
    mock_doc = MagicMock()
    mock_doc.exists = exists
    mock_doc.to_dict.return_value = data or {}
    mock_db.collection.return_value.document.return_value.get.return_value = mock_doc
    return mock_db


class TestAuthenticateInternal:
    """Tests for authenticate_internal."""

    @pytest.mark.asyncio
    async def test_rejects_missing_header(self):
        request = _make_request(auth_header=None)

        with pytest.raises(InternalAuthError, match="Missing"):
            await authenticate_internal(request)

    @pytest.mark.asyncio
    async def test_rejects_non_bearer(self):
        request = _make_request(auth_header="Basic abc123")

        with pytest.raises(InternalAuthError, match="Missing"):
            await authenticate_internal(request)

    @pytest.mark.asyncio
    async def test_rejects_non_internal_prefix(self):
        request = _make_request(auth_header="Bearer cs_live_abc123")

        with pytest.raises(InternalAuthError, match="Not an internal"):
            await authenticate_internal(request)

    @pytest.mark.asyncio
    async def test_rejects_unknown_key(self):
        mock_db = _mock_firestore_doc(exists=False)
        request = _make_request(auth_header="Bearer cs_internal_abc123")

        with (
            patch("src.api.internal_auth.firestore.Client", return_value=mock_db),
            pytest.raises(InternalAuthError, match="Invalid"),
        ):
            await authenticate_internal(request)

    @pytest.mark.asyncio
    async def test_rejects_disabled_key(self):
        mock_db = _mock_firestore_doc(
            exists=True,
            data={"active": False, "tier": "internal", "service": "app-scanner"},
        )
        request = _make_request(auth_header="Bearer cs_internal_abc123")

        with (
            patch("src.api.internal_auth.firestore.Client", return_value=mock_db),
            pytest.raises(InternalAuthError, match="disabled"),
        ):
            await authenticate_internal(request)

    @pytest.mark.asyncio
    async def test_rejects_non_internal_tier(self):
        mock_db = _mock_firestore_doc(
            exists=True,
            data={"active": True, "tier": "pro", "service": "external"},
        )
        request = _make_request(auth_header="Bearer cs_internal_abc123")

        with (
            patch("src.api.internal_auth.firestore.Client", return_value=mock_db),
            pytest.raises(InternalAuthError, match="Not an internal"),
        ):
            await authenticate_internal(request)

    @pytest.mark.asyncio
    async def test_accepts_valid_internal_key(self):
        mock_db = _mock_firestore_doc(
            exists=True,
            data={"active": True, "tier": "internal", "service": "app-scanner"},
        )
        request = _make_request(auth_header="Bearer cs_internal_abc123")

        key_hash = hashlib.sha256("cs_internal_abc123".encode()).hexdigest()

        with patch("src.api.internal_auth.firestore.Client", return_value=mock_db):
            result = await authenticate_internal(request)

        assert isinstance(result, InternalAuthContext)
        assert result.api_key_id == key_hash
        assert result.service == "app-scanner"

    @pytest.mark.asyncio
    async def test_hashes_key_with_sha256(self):
        """Verifies the key is looked up by its SHA-256 hash."""
        mock_db = _mock_firestore_doc(
            exists=True,
            data={"active": True, "tier": "internal", "service": "test"},
        )
        request = _make_request(auth_header="Bearer cs_internal_test_key")

        expected_hash = hashlib.sha256("cs_internal_test_key".encode()).hexdigest()

        with patch("src.api.internal_auth.firestore.Client", return_value=mock_db):
            await authenticate_internal(request)

        # Verify it looked up the correct hash
        mock_db.collection.return_value.document.assert_called_with(expected_hash)
