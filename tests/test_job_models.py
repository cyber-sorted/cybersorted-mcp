"""Tests for job system Pydantic models."""

from __future__ import annotations

from unittest.mock import patch

from src.jobs.models import (
    JobConfig,
    JobProgress,
    JobSource,
    JobStatus,
    PentestJob,
    ScanAlert,
    ScanLevel,
    ScanResults,
    ScanStats,
)


class TestJobConfig:
    """Tests for JobConfig model."""

    def test_defaults(self):
        config = JobConfig(target_url="https://example.com")
        assert config.target_url == "https://example.com"
        assert config.scan_level == ScanLevel.LIGHT
        assert config.scope is None
        assert config.policy is None

    def test_custom_level(self):
        config = JobConfig(target_url="https://example.com", scan_level=ScanLevel.DEEP)
        assert config.scan_level == ScanLevel.DEEP


class TestJobProgress:
    """Tests for JobProgress model."""

    def test_defaults(self):
        progress = JobProgress()
        assert progress.phase == "queued"
        assert progress.spider_progress == 0
        assert progress.active_scan_progress == 0
        assert progress.message == ""

    def test_clamps_progress(self):
        progress = JobProgress(spider_progress=50, active_scan_progress=75)
        assert progress.spider_progress == 50
        assert progress.active_scan_progress == 75


class TestScanResults:
    """Tests for ScanResults model."""

    def test_defaults(self):
        results = ScanResults()
        assert results.high == 0
        assert results.medium == 0
        assert results.low == 0
        assert results.informational == 0
        assert results.score == 100

    def test_custom_values(self):
        results = ScanResults(high=3, medium=5, low=10, informational=20, score=42)
        assert results.high == 3
        assert results.score == 42


class TestPentestJob:
    """Tests for PentestJob model."""

    def test_creation(self):
        job = PentestJob(
            job_id="test-123",
            source=JobSource.MCP,
            config=JobConfig(target_url="https://example.com"),
            container_image="cybersorted/zap-worker:latest",
        )
        assert job.job_id == "test-123"
        assert job.source == JobSource.MCP
        assert job.status == JobStatus.QUEUED
        assert job.config.target_url == "https://example.com"
        assert job.alerts == []
        assert job.results is None
        assert job.company_id is None

    def test_app_scanner_source(self):
        job = PentestJob(
            job_id="test-456",
            source=JobSource.APP_SCANNER,
            config=JobConfig(target_url="https://example.com"),
            container_image="cybersorted/zap-worker:latest",
            company_id="comp-123",
            scan_id="scan-789",
        )
        assert job.source == JobSource.APP_SCANNER
        assert job.company_id == "comp-123"
        assert job.scan_id == "scan-789"

    def test_to_firestore_strips_none(self):
        """to_firestore should remove None values."""
        job = PentestJob(
            job_id="test-123",
            source=JobSource.MCP,
            config=JobConfig(target_url="https://example.com"),
            container_image="cybersorted/zap-worker:latest",
        )
        with patch("google.cloud.firestore.SERVER_TIMESTAMP", "MOCK_TIMESTAMP"):
            data = job.to_firestore()

        # None fields should be stripped
        assert "api_key_id" not in data
        assert "company_id" not in data
        assert "scan_id" not in data
        assert "results" not in data
        assert "error_message" not in data

        # Required fields should be present
        assert data["job_id"] == "test-123"
        assert data["source"] == "mcp"
        assert data["status"] == "queued"


class TestScanAlert:
    """Tests for ScanAlert model."""

    def test_creation(self):
        alert = ScanAlert(
            name="SQL Injection",
            severity="High",
            url="https://example.com/login",
            cweid="89",
        )
        assert alert.name == "SQL Injection"
        assert alert.severity == "High"
        assert alert.cweid == "89"

    def test_defaults(self):
        alert = ScanAlert(name="Test", severity="Low")
        assert alert.url == ""
        assert alert.description == ""
        assert alert.solution == ""


class TestEnums:
    """Tests for enum values."""

    def test_job_status_values(self):
        assert JobStatus.QUEUED.value == "queued"
        assert JobStatus.DISPATCHED.value == "dispatched"
        assert JobStatus.RUNNING.value == "running"
        assert JobStatus.COMPLETED.value == "completed"
        assert JobStatus.FAILED.value == "failed"
        assert JobStatus.CANCELLED.value == "cancelled"

    def test_job_source_values(self):
        assert JobSource.MCP.value == "mcp"
        assert JobSource.APP_SCANNER.value == "app-scanner"

    def test_scan_level_values(self):
        assert ScanLevel.LIGHT.value == "light"
        assert ScanLevel.DEEP.value == "deep"
        assert ScanLevel.AGGRESSIVE.value == "aggressive"
