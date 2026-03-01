"""Tests for job manager (Firestore CRUD)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.jobs.manager import (
    complete_job,
    create_job,
    fail_job,
    get_job,
    update_progress,
    update_status,
)
from src.jobs.models import (
    JobConfig,
    JobProgress,
    JobSource,
    JobStatus,
    ScanAlert,
    ScanResults,
    ScanStats,
)


def _mock_firestore():
    """Create a mock Firestore client with collection/document chain."""
    mock_db = MagicMock()
    mock_doc_ref = MagicMock()
    mock_db.collection.return_value.document.return_value = mock_doc_ref
    return mock_db, mock_doc_ref


class TestCreateJob:
    """Tests for create_job."""

    @pytest.mark.asyncio
    async def test_creates_job_in_firestore(self):
        mock_db, mock_doc_ref = _mock_firestore()

        with patch("src.jobs.manager._get_db", return_value=mock_db):
            job = await create_job(
                source=JobSource.MCP,
                config=JobConfig(target_url="https://example.com"),
                container_image="cybersorted/zap-worker:latest",
                api_key_id="key-hash-123",
            )

        assert job.source == JobSource.MCP
        assert job.config.target_url == "https://example.com"
        assert job.api_key_id == "key-hash-123"
        assert job.status == JobStatus.QUEUED
        mock_doc_ref.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_creates_app_scanner_job(self):
        mock_db, mock_doc_ref = _mock_firestore()

        with patch("src.jobs.manager._get_db", return_value=mock_db):
            job = await create_job(
                source=JobSource.APP_SCANNER,
                config=JobConfig(target_url="https://example.com"),
                container_image="cybersorted/zap-worker:latest",
                company_id="comp-123",
                scan_id="scan-456",
            )

        assert job.source == JobSource.APP_SCANNER
        assert job.company_id == "comp-123"
        assert job.scan_id == "scan-456"

    @pytest.mark.asyncio
    async def test_generates_uuid(self):
        mock_db, mock_doc_ref = _mock_firestore()

        with patch("src.jobs.manager._get_db", return_value=mock_db):
            job = await create_job(
                source=JobSource.MCP,
                config=JobConfig(target_url="https://example.com"),
                container_image="test:latest",
            )

        assert len(job.job_id) == 36  # UUID format


class TestGetJob:
    """Tests for get_job."""

    @pytest.mark.asyncio
    async def test_returns_none_for_missing_job(self):
        mock_db, mock_doc_ref = _mock_firestore()
        mock_doc = MagicMock()
        mock_doc.exists = False
        mock_doc_ref.get.return_value = mock_doc

        with patch("src.jobs.manager._get_db", return_value=mock_db):
            result = await get_job("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_job_for_existing_doc(self):
        mock_db, mock_doc_ref = _mock_firestore()
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "job_id": "test-123",
            "source": "mcp",
            "tool": "scan_web_application",
            "status": "queued",
            "config": {"target_url": "https://example.com", "scan_level": "light"},
            "progress": {"phase": "queued", "spider_progress": 0, "active_scan_progress": 0, "message": ""},
            "alerts": [],
            "container_image": "test:latest",
            "created_at": "2026-01-01T00:00:00",
            "updated_at": "2026-01-01T00:00:00",
        }
        mock_doc_ref.get.return_value = mock_doc

        with patch("src.jobs.manager._get_db", return_value=mock_db):
            result = await get_job("test-123")

        assert result is not None
        assert result.job_id == "test-123"
        assert result.status == JobStatus.QUEUED


class TestUpdateStatus:
    """Tests for update_status."""

    @pytest.mark.asyncio
    async def test_updates_status(self):
        mock_db, mock_doc_ref = _mock_firestore()

        with patch("src.jobs.manager._get_db", return_value=mock_db):
            await update_status("test-123", JobStatus.DISPATCHED, container_id="abc123")

        call_args = mock_doc_ref.update.call_args[0][0]
        assert call_args["status"] == "dispatched"
        assert call_args["container_id"] == "abc123"

    @pytest.mark.asyncio
    async def test_sets_started_at_on_running(self):
        mock_db, mock_doc_ref = _mock_firestore()

        with patch("src.jobs.manager._get_db", return_value=mock_db):
            await update_status("test-123", JobStatus.RUNNING)

        call_args = mock_doc_ref.update.call_args[0][0]
        assert call_args["status"] == "running"
        assert "started_at" in call_args

    @pytest.mark.asyncio
    async def test_sets_completed_at_on_completion(self):
        mock_db, mock_doc_ref = _mock_firestore()

        with patch("src.jobs.manager._get_db", return_value=mock_db):
            await update_status("test-123", JobStatus.COMPLETED)

        call_args = mock_doc_ref.update.call_args[0][0]
        assert "completed_at" in call_args


class TestUpdateProgress:
    """Tests for update_progress."""

    @pytest.mark.asyncio
    async def test_writes_progress(self):
        mock_db, mock_doc_ref = _mock_firestore()
        progress = JobProgress(phase="crawling", spider_progress=50, message="Discovering pages...")

        with patch("src.jobs.manager._get_db", return_value=mock_db):
            await update_progress("test-123", progress)

        call_args = mock_doc_ref.update.call_args[0][0]
        assert call_args["progress"]["phase"] == "crawling"
        assert call_args["progress"]["spider_progress"] == 50


class TestCompleteJob:
    """Tests for complete_job."""

    @pytest.mark.asyncio
    async def test_writes_results_and_alerts(self):
        mock_db, mock_doc_ref = _mock_firestore()
        results = ScanResults(high=2, medium=5, low=10, score=55)
        alerts = [ScanAlert(name="SQL Injection", severity="High")]
        stats = ScanStats(urls_crawled=50, requests_sent=200, duration_seconds=120)

        with patch("src.jobs.manager._get_db", return_value=mock_db):
            await complete_job("test-123", results=results, alerts=alerts, scan_stats=stats)

        call_args = mock_doc_ref.update.call_args[0][0]
        assert call_args["status"] == "completed"
        assert call_args["results"]["high"] == 2
        assert call_args["results"]["score"] == 55
        assert len(call_args["alerts"]) == 1
        assert call_args["alerts"][0]["name"] == "SQL Injection"
        assert call_args["scan_stats"]["urls_crawled"] == 50


class TestFailJob:
    """Tests for fail_job."""

    @pytest.mark.asyncio
    async def test_marks_job_as_failed(self):
        mock_db, mock_doc_ref = _mock_firestore()

        with patch("src.jobs.manager._get_db", return_value=mock_db):
            await fail_job("test-123", "Container crashed")

        call_args = mock_doc_ref.update.call_args[0][0]
        assert call_args["status"] == "failed"
        assert call_args["error_message"] == "Container crashed"
