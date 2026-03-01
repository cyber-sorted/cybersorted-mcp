"""Tests for scan_web_application MCP tool."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.jobs.dispatcher import ContainerInfo, DispatchError
from src.jobs.models import (
    JobConfig,
    JobProgress,
    JobSource,
    JobStatus,
    PentestJob,
    ScanAlert,
    ScanResults,
    ScanStats,
)
from src.tools.scanning.web_application import scan_web_application


def _make_job(status: JobStatus = JobStatus.QUEUED, **kwargs) -> PentestJob:
    """Create a test PentestJob."""
    defaults = {
        "job_id": "job-123",
        "source": JobSource.MCP,
        "config": JobConfig(target_url="https://example.com"),
        "container_image": "test:latest",
        "status": status,
    }
    defaults.update(kwargs)
    return PentestJob(**defaults)


class TestScanWebApplication:
    """Tests for scan_web_application."""

    @pytest.mark.asyncio
    async def test_rejects_invalid_scan_level(self):
        result = await scan_web_application(
            target_url="https://example.com",
            scan_level="invalid",
        )
        assert "error" in result
        assert "Invalid scan_level" in result["error"]

    @pytest.mark.asyncio
    async def test_handles_dispatch_failure(self):
        job = _make_job()

        with (
            patch(
                "src.tools.scanning.web_application.create_job",
                new_callable=AsyncMock,
                return_value=job,
            ),
            patch(
                "src.tools.scanning.web_application.launch_worker",
                new_callable=AsyncMock,
                side_effect=DispatchError("No capacity"),
            ),
            patch(
                "src.tools.scanning.web_application.fail_job",
                new_callable=AsyncMock,
            ),
        ):
            result = await scan_web_application(target_url="https://example.com")

        assert result["status"] == "failed"
        assert "No capacity" in result["error"]

    @pytest.mark.asyncio
    async def test_returns_results_on_completion(self):
        queued_job = _make_job(status=JobStatus.DISPATCHED)
        completed_job = _make_job(
            status=JobStatus.COMPLETED,
            results=ScanResults(high=1, medium=3, low=5, informational=10, score=72),
            alerts=[
                ScanAlert(
                    name="XSS",
                    severity="High",
                    url="https://example.com/search",
                    description="Cross-site scripting",
                    solution="Encode output",
                    cweid="79",
                    wascid="8",
                ),
            ],
            scan_stats=ScanStats(urls_crawled=50, requests_sent=200, duration_seconds=120),
        )

        with (
            patch(
                "src.tools.scanning.web_application.create_job",
                new_callable=AsyncMock,
                return_value=queued_job,
            ),
            patch(
                "src.tools.scanning.web_application.launch_worker",
                new_callable=AsyncMock,
                return_value=ContainerInfo(container_id="abc", name="test", image="test:latest"),
            ),
            patch(
                "src.tools.scanning.web_application.update_status",
                new_callable=AsyncMock,
            ),
            patch(
                "src.tools.scanning.web_application.get_job",
                new_callable=AsyncMock,
                return_value=completed_job,
            ),
        ):
            result = await scan_web_application(target_url="https://example.com")

        assert result["status"] == "completed"
        assert result["summary"]["high"] == 1
        assert result["summary"]["security_score"] == 72
        assert result["vulnerability_count"] == 1
        assert result["vulnerabilities"][0]["name"] == "XSS"
        assert result["stats"]["urls_crawled"] == 50

    @pytest.mark.asyncio
    async def test_handles_failed_scan(self):
        queued_job = _make_job(status=JobStatus.DISPATCHED)
        failed_job = _make_job(
            status=JobStatus.FAILED,
            error_message="Container crashed",
        )

        with (
            patch(
                "src.tools.scanning.web_application.create_job",
                new_callable=AsyncMock,
                return_value=queued_job,
            ),
            patch(
                "src.tools.scanning.web_application.launch_worker",
                new_callable=AsyncMock,
                return_value=ContainerInfo(container_id="abc", name="test", image="test:latest"),
            ),
            patch(
                "src.tools.scanning.web_application.update_status",
                new_callable=AsyncMock,
            ),
            patch(
                "src.tools.scanning.web_application.get_job",
                new_callable=AsyncMock,
                return_value=failed_job,
            ),
        ):
            result = await scan_web_application(target_url="https://example.com")

        assert result["status"] == "failed"
        assert "Container crashed" in result["error"]
