"""Tests for bridge (pentest-jobs → security-scans sync)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.jobs.bridge import sync_to_security_scan
from src.jobs.models import (
    JobConfig,
    JobProgress,
    JobSource,
    JobStatus,
    PentestJob,
    ScanAlert,
    ScanResults,
)


def _make_job(**kwargs) -> PentestJob:
    """Create a test PentestJob with sensible defaults."""
    defaults = {
        "job_id": "job-123",
        "source": JobSource.APP_SCANNER,
        "config": JobConfig(target_url="https://example.com"),
        "container_image": "test:latest",
        "company_id": "comp-123",
        "scan_id": "scan-456",
    }
    defaults.update(kwargs)
    return PentestJob(**defaults)


def _mock_firestore():
    """Create a mock Firestore client with collection chain."""
    mock_db = MagicMock()
    mock_scan_ref = MagicMock()
    mock_db.collection.return_value.document.return_value.collection.return_value.document.return_value = mock_scan_ref
    return mock_db, mock_scan_ref


class TestSyncToSecurityScan:
    """Tests for sync_to_security_scan."""

    @pytest.mark.asyncio
    async def test_skips_if_no_company_id(self):
        job = _make_job(company_id=None)

        with patch("src.jobs.bridge._get_bridge_db") as mock_get_bridge_db:
            await sync_to_security_scan(job)
            mock_get_bridge_db.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_if_no_scan_id(self):
        job = _make_job(scan_id=None)

        with patch("src.jobs.bridge._get_bridge_db") as mock_get_bridge_db:
            await sync_to_security_scan(job)
            mock_get_bridge_db.assert_not_called()

    @pytest.mark.asyncio
    async def test_syncs_queued_status(self):
        mock_db, mock_scan_ref = _mock_firestore()
        job = _make_job(status=JobStatus.QUEUED)

        with patch("src.jobs.bridge._get_bridge_db", return_value=mock_db):
            await sync_to_security_scan(job)

        call_args = mock_scan_ref.update.call_args[0][0]
        assert call_args["status"] == "pending"

    @pytest.mark.asyncio
    async def test_syncs_running_crawling_phase(self):
        mock_db, mock_scan_ref = _mock_firestore()
        job = _make_job(
            status=JobStatus.RUNNING,
            progress=JobProgress(phase="crawling", spider_progress=50),
        )

        with patch("src.jobs.bridge._get_bridge_db", return_value=mock_db):
            await sync_to_security_scan(job)

        call_args = mock_scan_ref.update.call_args[0][0]
        assert call_args["status"] == "crawling"
        assert call_args["spiderProgress"] == 50
        assert call_args["activeScanProgress"] == 0

    @pytest.mark.asyncio
    async def test_syncs_scanning_phase(self):
        mock_db, mock_scan_ref = _mock_firestore()
        job = _make_job(
            status=JobStatus.RUNNING,
            progress=JobProgress(phase="scanning", spider_progress=100, active_scan_progress=75),
        )

        with patch("src.jobs.bridge._get_bridge_db", return_value=mock_db):
            await sync_to_security_scan(job)

        call_args = mock_scan_ref.update.call_args[0][0]
        assert call_args["status"] == "scanning"
        assert call_args["spiderProgress"] == 100
        assert call_args["activeScanProgress"] == 75

    @pytest.mark.asyncio
    async def test_syncs_completed_with_results(self):
        mock_db, mock_scan_ref = _mock_firestore()
        job = _make_job(
            status=JobStatus.COMPLETED,
            results=ScanResults(high=2, medium=5, low=10, score=55),
            alerts=[
                ScanAlert(
                    name="SQL Injection",
                    severity="High",
                    url="https://example.com/login",
                    description="SQL injection vulnerability",
                    solution="Use parameterised queries",
                    cweid="89",
                    wascid="19",
                    confidence="High",
                    reference="https://owasp.org/sql-injection",
                ),
            ],
            progress=JobProgress(phase="completed", spider_progress=100, active_scan_progress=100),
        )

        with patch("src.jobs.bridge._get_bridge_db", return_value=mock_db):
            await sync_to_security_scan(job)

        call_args = mock_scan_ref.update.call_args[0][0]
        assert call_args["status"] == "completed"
        assert call_args["results"]["high"] == 2
        assert call_args["results"]["score"] == 55
        assert len(call_args["alerts"]) == 1
        assert call_args["alerts"][0]["alert"] == "SQL Injection"
        assert call_args["alerts"][0]["risk"] == "High"
        assert call_args["alerts"][0]["cweid"] == "89"

    @pytest.mark.asyncio
    async def test_syncs_failed_with_error(self):
        mock_db, mock_scan_ref = _mock_firestore()
        job = _make_job(
            status=JobStatus.FAILED,
            error_message="Container crashed",
            progress=JobProgress(phase="failed"),
        )

        with patch("src.jobs.bridge._get_bridge_db", return_value=mock_db):
            await sync_to_security_scan(job)

        call_args = mock_scan_ref.update.call_args[0][0]
        assert call_args["status"] == "failed"
        assert call_args["errorMessage"] == "Container crashed"

    @pytest.mark.asyncio
    async def test_handles_firestore_error(self):
        """sync_to_security_scan should not raise on Firestore errors."""
        mock_db, mock_scan_ref = _mock_firestore()
        mock_scan_ref.update.side_effect = Exception("Firestore error")
        job = _make_job()

        with patch("src.jobs.bridge._get_bridge_db", return_value=mock_db):
            # Should not raise
            await sync_to_security_scan(job)
