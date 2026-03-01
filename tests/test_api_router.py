"""Tests for REST API router."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.api.internal_auth import InternalAuthContext, InternalAuthError
from src.jobs.models import (
    JobConfig,
    JobProgress,
    JobSource,
    JobStatus,
    PentestJob,
    ScanResults,
)
from src.server import app

client = TestClient(app)


def _make_job(**kwargs) -> PentestJob:
    """Create a test PentestJob."""
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


def _auth_patch():
    """Patch authenticate_internal to return a valid context."""
    return patch(
        "src.api.router.authenticate_internal",
        new_callable=AsyncMock,
        return_value=InternalAuthContext(api_key_id="hash123", service="app-scanner"),
    )


class TestStartScan:
    """Tests for POST /api/v1/scans/start."""

    def test_rejects_unauthenticated(self):
        with patch(
            "src.api.router.authenticate_internal",
            new_callable=AsyncMock,
            side_effect=InternalAuthError("Missing auth"),
        ):
            resp = client.post(
                "/api/v1/scans/start",
                json={
                    "company_id": "comp-123",
                    "scan_id": "scan-456",
                    "target_url": "https://example.com",
                },
            )
        assert resp.status_code == 401

    def test_starts_scan_successfully(self):
        job = _make_job()

        with (
            _auth_patch(),
            patch("src.api.router.create_job", new_callable=AsyncMock, return_value=job),
            patch("src.api.router.launch_worker", new_callable=AsyncMock) as mock_launch,
            patch("src.api.router.update_status", new_callable=AsyncMock),
        ):
            from src.jobs.dispatcher import ContainerInfo

            mock_launch.return_value = ContainerInfo(
                container_id="abc123", name="zap-worker-job-123", image="test:latest"
            )

            resp = client.post(
                "/api/v1/scans/start",
                json={
                    "company_id": "comp-123",
                    "scan_id": "scan-456",
                    "target_url": "https://example.com",
                    "scan_level": "light",
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["job_id"] == "job-123"
        assert data["status"] == "queued"

    def test_returns_503_on_dispatch_failure(self):
        from src.jobs.dispatcher import DispatchError

        job = _make_job()

        with (
            _auth_patch(),
            patch("src.api.router.create_job", new_callable=AsyncMock, return_value=job),
            patch(
                "src.api.router.launch_worker",
                new_callable=AsyncMock,
                side_effect=DispatchError("Concurrent scan limit reached"),
            ),
            patch("src.api.router.fail_job", new_callable=AsyncMock),
            patch("src.api.router.get_job", new_callable=AsyncMock, return_value=job),
            patch("src.api.router.sync_to_security_scan", new_callable=AsyncMock),
        ):
            resp = client.post(
                "/api/v1/scans/start",
                json={
                    "company_id": "comp-123",
                    "scan_id": "scan-456",
                    "target_url": "https://example.com",
                },
            )

        assert resp.status_code == 503
        assert "Concurrent scan limit" in resp.json()["error"]


class TestGetScanStatus:
    """Tests for GET /api/v1/scans/{id}/status."""

    def test_returns_job_status(self):
        job = _make_job(
            status=JobStatus.RUNNING,
            progress=JobProgress(phase="scanning", spider_progress=100, active_scan_progress=50),
        )

        with (
            _auth_patch(),
            patch("src.api.router.get_job", new_callable=AsyncMock, return_value=job),
            patch("src.api.router.sync_to_security_scan", new_callable=AsyncMock),
        ):
            resp = client.get("/api/v1/scans/job-123/status")

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "running"
        assert data["progress"]["spider_progress"] == 100
        assert data["progress"]["active_scan_progress"] == 50

    def test_returns_404_for_missing_job(self):
        with (
            _auth_patch(),
            patch("src.api.router.get_job", new_callable=AsyncMock, return_value=None),
        ):
            resp = client.get("/api/v1/scans/nonexistent/status")

        assert resp.status_code == 404

    def test_returns_completed_results(self):
        job = _make_job(
            status=JobStatus.COMPLETED,
            results=ScanResults(high=2, medium=5, score=55),
            progress=JobProgress(phase="completed", spider_progress=100, active_scan_progress=100),
        )

        with (
            _auth_patch(),
            patch("src.api.router.get_job", new_callable=AsyncMock, return_value=job),
            patch("src.api.router.sync_to_security_scan", new_callable=AsyncMock),
        ):
            resp = client.get("/api/v1/scans/job-123/status")

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["results"]["high"] == 2
        assert data["results"]["score"] == 55


class TestCancelScan:
    """Tests for POST /api/v1/scans/{id}/cancel."""

    def test_cancels_running_scan(self):
        job = _make_job(status=JobStatus.RUNNING, container_id="abc123")

        with (
            _auth_patch(),
            patch("src.api.router.get_job", new_callable=AsyncMock, side_effect=[job, job]),
            patch("src.api.router.stop_worker", new_callable=AsyncMock, return_value=True),
            patch("src.api.router.update_status", new_callable=AsyncMock),
            patch("src.api.router.sync_to_security_scan", new_callable=AsyncMock),
        ):
            resp = client.post("/api/v1/scans/job-123/cancel")

        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"

    def test_returns_404_for_missing_job(self):
        with (
            _auth_patch(),
            patch("src.api.router.get_job", new_callable=AsyncMock, return_value=None),
        ):
            resp = client.post("/api/v1/scans/nonexistent/cancel")

        assert resp.status_code == 404

    def test_handles_already_completed(self):
        job = _make_job(status=JobStatus.COMPLETED)

        with (
            _auth_patch(),
            patch("src.api.router.get_job", new_callable=AsyncMock, return_value=job),
        ):
            resp = client.post("/api/v1/scans/job-123/cancel")

        assert resp.status_code == 200
        assert "already completed" in resp.json()["message"]
