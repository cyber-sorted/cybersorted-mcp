"""Tests for passive reconnaissance tool."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.tools.recon.passive import (
    _detect_technologies,
    _enumerate_subdomains,
    _lookup_dns,
    _lookup_rdap,
    _query_ct_logs,
    recon_passive,
)


class TestReconPassive:
    """Tests for the main recon_passive function."""

    @pytest.mark.asyncio
    async def test_returns_expected_structure(self):
        """recon_passive returns all expected keys."""
        with (
            patch("src.tools.recon.passive._lookup_dns", new_callable=AsyncMock) as mock_dns,
            patch(
                "src.tools.recon.passive._enumerate_subdomains", new_callable=AsyncMock
            ) as mock_subs,
            patch("src.tools.recon.passive._lookup_rdap", new_callable=AsyncMock) as mock_rdap,
            patch(
                "src.tools.recon.passive._detect_technologies", new_callable=AsyncMock
            ) as mock_tech,
            patch(
                "src.tools.recon.passive._query_ct_logs", new_callable=AsyncMock
            ) as mock_certs,
        ):
            mock_dns.return_value = [{"type": "A", "value": "93.184.216.34", "ttl": 300}]
            mock_subs.return_value = ["www.example.com", "mail.example.com"]
            mock_rdap.return_value = {"name": "example.com", "registrar": "IANA"}
            mock_tech.return_value = [{"source": "header:server", "value": "nginx"}]
            mock_certs.return_value = [{"issuer": "DigiCert", "common_name": "example.com"}]

            result = await recon_passive("example.com")

            assert result["target"] == "example.com"
            assert result["depth"] == "standard"
            assert isinstance(result["dns_records"], list)
            assert isinstance(result["domains"], list)
            assert isinstance(result["whois"], dict)
            assert isinstance(result["technologies"], list)
            assert isinstance(result["certificates"], list)

    @pytest.mark.asyncio
    async def test_strips_protocol_prefix(self):
        """recon_passive strips http:// and https:// from target."""
        with (
            patch("src.tools.recon.passive._lookup_dns", new_callable=AsyncMock) as mock_dns,
            patch(
                "src.tools.recon.passive._enumerate_subdomains", new_callable=AsyncMock
            ) as mock_subs,
            patch("src.tools.recon.passive._lookup_rdap", new_callable=AsyncMock) as mock_rdap,
            patch(
                "src.tools.recon.passive._detect_technologies", new_callable=AsyncMock
            ) as mock_tech,
            patch(
                "src.tools.recon.passive._query_ct_logs", new_callable=AsyncMock
            ) as mock_certs,
        ):
            mock_dns.return_value = []
            mock_subs.return_value = []
            mock_rdap.return_value = {}
            mock_tech.return_value = []
            mock_certs.return_value = []

            result = await recon_passive("https://example.com")
            assert result["target"] == "example.com"

    @pytest.mark.asyncio
    async def test_deep_depth_passed_through(self):
        """Depth parameter is included in results."""
        with (
            patch("src.tools.recon.passive._lookup_dns", new_callable=AsyncMock) as mock_dns,
            patch(
                "src.tools.recon.passive._enumerate_subdomains", new_callable=AsyncMock
            ) as mock_subs,
            patch("src.tools.recon.passive._lookup_rdap", new_callable=AsyncMock) as mock_rdap,
            patch(
                "src.tools.recon.passive._detect_technologies", new_callable=AsyncMock
            ) as mock_tech,
            patch(
                "src.tools.recon.passive._query_ct_logs", new_callable=AsyncMock
            ) as mock_certs,
        ):
            mock_dns.return_value = []
            mock_subs.return_value = []
            mock_rdap.return_value = {}
            mock_tech.return_value = []
            mock_certs.return_value = []

            result = await recon_passive("example.com", depth="deep")
            assert result["depth"] == "deep"


class TestLookupDns:
    """Tests for DNS record lookups."""

    @pytest.mark.asyncio
    async def test_returns_records(self):
        """DNS lookup returns structured records."""
        mock_rdata = MagicMock()
        mock_rdata.__str__ = lambda self: "93.184.216.34"

        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda self: iter([mock_rdata])
        mock_answer.ttl = 300

        with patch("src.tools.recon.passive.dns.resolver.Resolver") as mock_resolver_cls:
            mock_resolver = MagicMock()
            mock_resolver_cls.return_value = mock_resolver
            mock_resolver.resolve.return_value = mock_answer

            records = await _lookup_dns("example.com")

            assert len(records) > 0
            assert records[0]["type"] in [
                "A",
                "AAAA",
                "MX",
                "TXT",
                "CNAME",
                "NS",
                "SOA",
            ]
            assert records[0]["value"] == "93.184.216.34"
            assert records[0]["ttl"] == 300

    @pytest.mark.asyncio
    async def test_handles_nxdomain(self):
        """DNS lookup gracefully handles non-existent domains."""
        import dns.resolver

        with patch("src.tools.recon.passive.dns.resolver.Resolver") as mock_resolver_cls:
            mock_resolver = MagicMock()
            mock_resolver_cls.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

            records = await _lookup_dns("nonexistent.invalid")
            assert records == []


class TestEnumerateSubdomains:
    """Tests for subdomain enumeration via crt.sh."""

    @pytest.mark.asyncio
    async def test_parses_crtsh_response(self):
        """Subdomain enumeration parses crt.sh JSON correctly."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"name_value": "www.example.com"},
            {"name_value": "mail.example.com\nsmtp.example.com"},
            {"name_value": "*.example.com"},  # wildcard — should be skipped
        ]

        client = AsyncMock()
        client.get.return_value = mock_response

        subdomains = await _enumerate_subdomains(client, "example.com", "standard")

        assert "www.example.com" in subdomains
        assert "mail.example.com" in subdomains
        assert "smtp.example.com" in subdomains
        # Wildcards should be filtered out
        assert "*.example.com" not in subdomains

    @pytest.mark.asyncio
    async def test_handles_crtsh_error(self):
        """Subdomain enumeration handles crt.sh errors gracefully."""
        client = AsyncMock()
        client.get.side_effect = Exception("Connection failed")

        subdomains = await _enumerate_subdomains(client, "example.com", "standard")
        assert subdomains == []


class TestLookupRdap:
    """Tests for RDAP/WHOIS lookups."""

    @pytest.mark.asyncio
    async def test_parses_rdap_response(self):
        """RDAP lookup extracts domain registration data."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ldhName": "example.com",
            "status": ["active"],
            "nameservers": [{"ldhName": "ns1.example.com"}, {"ldhName": "ns2.example.com"}],
            "events": [
                {"eventAction": "registration", "eventDate": "1995-08-14T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2026-08-13T00:00:00Z"},
            ],
        }

        client = AsyncMock()
        client.get.return_value = mock_response

        whois = await _lookup_rdap(client, "example.com")

        assert whois["name"] == "example.com"
        assert "ns1.example.com" in whois["nameservers"]
        assert whois["registered"] == "1995-08-14T00:00:00Z"

    @pytest.mark.asyncio
    async def test_handles_rdap_error(self):
        """RDAP lookup handles errors gracefully."""
        client = AsyncMock()
        client.get.side_effect = Exception("Connection failed")

        whois = await _lookup_rdap(client, "example.com")
        assert whois == {}


class TestDetectTechnologies:
    """Tests for technology detection from HTTP headers."""

    @pytest.mark.asyncio
    async def test_detects_server_header(self):
        """Technology detection picks up Server header."""
        mock_response = MagicMock()
        mock_response.headers = {
            "server": "nginx/1.24.0",
            "content-type": "text/html; charset=utf-8",
            "x-powered-by": "Express",
        }

        client = AsyncMock()
        client.get.return_value = mock_response

        techs = await _detect_technologies(client, "example.com")

        sources = [t["source"] for t in techs]
        assert "header:server" in sources
        assert "header:x-powered-by" in sources

    @pytest.mark.asyncio
    async def test_handles_connection_error(self):
        """Technology detection handles unreachable targets."""
        client = AsyncMock()
        client.get.side_effect = Exception("Connection refused")

        techs = await _detect_technologies(client, "example.com")
        assert techs == []


class TestQueryCtLogs:
    """Tests for Certificate Transparency log queries."""

    @pytest.mark.asyncio
    async def test_parses_ct_entries(self):
        """CT log query parses crt.sh certificate entries."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "issuer_name": "C=US, O=DigiCert Inc",
                "common_name": "example.com",
                "name_value": "example.com",
                "not_before": "2024-01-01T00:00:00",
                "not_after": "2025-01-01T00:00:00",
                "serial_number": "ABC123",
            },
        ]

        client = AsyncMock()
        client.get.return_value = mock_response

        certs = await _query_ct_logs(client, "example.com")

        assert len(certs) == 1
        assert certs[0]["issuer"] == "C=US, O=DigiCert Inc"
        assert certs[0]["common_name"] == "example.com"

    @pytest.mark.asyncio
    async def test_deduplicates_by_serial(self):
        """CT log query deduplicates certificates by serial number."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"serial_number": "ABC123", "common_name": "example.com"},
            {"serial_number": "ABC123", "common_name": "example.com"},  # duplicate
            {"serial_number": "DEF456", "common_name": "www.example.com"},
        ]

        client = AsyncMock()
        client.get.return_value = mock_response

        certs = await _query_ct_logs(client, "example.com")
        assert len(certs) == 2
