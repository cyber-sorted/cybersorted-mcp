"""Tests for Docker dispatcher."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.jobs.dispatcher import (
    ContainerInfo,
    DispatchError,
    get_worker_status,
    launch_worker,
    stop_worker,
)


def _mock_docker_client(running_count: int = 0):
    """Create a mock Docker client."""
    mock_client = MagicMock()
    mock_client.containers.list.return_value = [MagicMock()] * running_count
    return mock_client


class TestLaunchWorker:
    """Tests for launch_worker."""

    @pytest.mark.asyncio
    async def test_launches_container(self):
        mock_client = _mock_docker_client(running_count=0)
        mock_container = MagicMock()
        mock_container.id = "abc123def456"
        mock_container.short_id = "abc123d"
        mock_client.containers.run.return_value = mock_container

        with patch("src.jobs.dispatcher._get_client", return_value=mock_client):
            result = await launch_worker(
                job_id="test-job-12345678",
                image="cybersorted/zap-worker:latest",
                env={"JOB_ID": "test-job-12345678", "TARGET_URL": "https://example.com"},
            )

        assert isinstance(result, ContainerInfo)
        assert result.container_id == "abc123def456"
        assert result.image == "cybersorted/zap-worker:latest"
        mock_client.containers.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_enforces_concurrent_limit(self):
        mock_client = _mock_docker_client(running_count=3)

        with (
            patch("src.jobs.dispatcher._get_client", return_value=mock_client),
            patch("src.jobs.dispatcher.settings") as mock_settings,
        ):
            mock_settings.MAX_CONCURRENT_SCANS = 3
            with pytest.raises(DispatchError, match="Concurrent scan limit"):
                await launch_worker(
                    job_id="test-123",
                    image="test:latest",
                    env={},
                )

    @pytest.mark.asyncio
    async def test_sets_resource_limits(self):
        mock_client = _mock_docker_client(running_count=0)
        mock_container = MagicMock()
        mock_container.id = "abc123"
        mock_container.short_id = "abc123"
        mock_client.containers.run.return_value = mock_container

        with patch("src.jobs.dispatcher._get_client", return_value=mock_client):
            await launch_worker(
                job_id="test-12345678",
                image="test:latest",
                env={},
                mem_limit="4g",
                cpu_count=2,
            )

        call_kwargs = mock_client.containers.run.call_args[1]
        assert call_kwargs["mem_limit"] == "4g"
        assert call_kwargs["nano_cpus"] == 2_000_000_000
        assert call_kwargs["remove"] is True  # --rm flag

    @pytest.mark.asyncio
    async def test_raises_on_docker_api_error(self):
        from docker.errors import APIError

        mock_client = _mock_docker_client(running_count=0)
        mock_client.containers.run.side_effect = APIError("Image not found")

        with patch("src.jobs.dispatcher._get_client", return_value=mock_client):
            with pytest.raises(DispatchError, match="Docker API error"):
                await launch_worker(
                    job_id="test-123",
                    image="nonexistent:latest",
                    env={},
                )

    @pytest.mark.asyncio
    async def test_container_name_includes_job_id(self):
        mock_client = _mock_docker_client(running_count=0)
        mock_container = MagicMock()
        mock_container.id = "abc123"
        mock_container.short_id = "abc123"
        mock_client.containers.run.return_value = mock_container

        with patch("src.jobs.dispatcher._get_client", return_value=mock_client):
            result = await launch_worker(
                job_id="abcdef12-3456-7890-abcd-ef1234567890",
                image="test:latest",
                env={},
            )

        assert result.name == "zap-worker-abcdef12"

    @pytest.mark.asyncio
    async def test_sets_labels(self):
        mock_client = _mock_docker_client(running_count=0)
        mock_container = MagicMock()
        mock_container.id = "abc123"
        mock_container.short_id = "abc123"
        mock_client.containers.run.return_value = mock_container

        with patch("src.jobs.dispatcher._get_client", return_value=mock_client):
            await launch_worker(
                job_id="test-12345678",
                image="test:latest",
                env={},
            )

        call_kwargs = mock_client.containers.run.call_args[1]
        assert call_kwargs["labels"]["cybersorted.job_id"] == "test-12345678"
        assert call_kwargs["labels"]["cybersorted.role"] == "worker"


class TestStopWorker:
    """Tests for stop_worker."""

    @pytest.mark.asyncio
    async def test_stops_running_container(self):
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_client.containers.get.return_value = mock_container

        with patch("src.jobs.dispatcher._get_client", return_value=mock_client):
            result = await stop_worker("abc123")

        assert result is True
        mock_container.stop.assert_called_once_with(timeout=10)

    @pytest.mark.asyncio
    async def test_returns_false_for_missing_container(self):
        from docker.errors import NotFound

        mock_client = MagicMock()
        mock_client.containers.get.side_effect = NotFound("Not found")

        with patch("src.jobs.dispatcher._get_client", return_value=mock_client):
            result = await stop_worker("missing123")

        assert result is False


class TestGetWorkerStatus:
    """Tests for get_worker_status."""

    @pytest.mark.asyncio
    async def test_returns_status(self):
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_client.containers.get.return_value = mock_container

        with patch("src.jobs.dispatcher._get_client", return_value=mock_client):
            status = await get_worker_status("abc123")

        assert status == "running"

    @pytest.mark.asyncio
    async def test_returns_none_for_missing(self):
        from docker.errors import NotFound

        mock_client = MagicMock()
        mock_client.containers.get.side_effect = NotFound("Not found")

        with patch("src.jobs.dispatcher._get_client", return_value=mock_client):
            status = await get_worker_status("missing123")

        assert status is None
