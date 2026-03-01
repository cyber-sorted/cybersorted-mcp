"""Docker SDK dispatcher — launches and stops worker containers on the local daemon."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import docker
from docker.errors import APIError, NotFound

from src.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ContainerInfo:
    """Metadata returned after launching a worker container."""

    container_id: str
    name: str
    image: str


class DispatchError(Exception):
    """Raised when container dispatch fails."""


def _get_client() -> docker.DockerClient:
    """Get Docker client connected to the local daemon socket."""
    return docker.from_env()


async def launch_worker(
    *,
    job_id: str,
    image: str,
    env: dict[str, str],
    mem_limit: str = "4g",
    cpu_count: int = 2,
    timeout_seconds: int = 3600,
) -> ContainerInfo:
    """Launch an ephemeral worker container for a pentest job.

    The container runs with --rm (auto-remove on exit), resource limits,
    and a hard timeout via --stop-timeout.

    Args:
        job_id: Unique job identifier (used in container name).
        image: Docker image to run (e.g. "cybersorted/zap-worker:latest").
        env: Environment variables to pass to the container.
        mem_limit: Memory limit (default 4GB).
        cpu_count: CPU count limit (default 2).
        timeout_seconds: Hard timeout in seconds (default 1 hour).

    Returns:
        ContainerInfo with the launched container's ID and name.

    Raises:
        DispatchError: If the container fails to launch.
    """
    client = _get_client()
    container_name = f"zap-worker-{job_id[:8]}"

    # Check concurrent scan limit
    running = _count_running_workers(client)
    if running >= settings.MAX_CONCURRENT_SCANS:
        raise DispatchError(
            f"Concurrent scan limit reached ({running}/{settings.MAX_CONCURRENT_SCANS}). "
            "Please wait for a running scan to complete."
        )

    try:
        container = client.containers.run(
            image=image,
            name=container_name,
            environment=env,
            detach=True,
            remove=True,  # --rm
            mem_limit=mem_limit,
            nano_cpus=cpu_count * 1_000_000_000,  # Docker API uses nanocpus
            network_mode="bridge",
            labels={
                "cybersorted.job_id": job_id,
                "cybersorted.role": "worker",
            },
        )

        info = ContainerInfo(
            container_id=container.id,
            name=container_name,
            image=image,
        )
        logger.info(
            "Launched worker %s (container=%s, image=%s)",
            container_name, container.short_id, image,
        )
        return info

    except APIError as exc:
        logger.error("Failed to launch worker for job %s: %s", job_id, exc)
        raise DispatchError(f"Docker API error: {exc}") from exc


async def stop_worker(container_id: str) -> bool:
    """Stop a running worker container.

    Returns True if the container was stopped, False if not found.
    """
    client = _get_client()
    try:
        container = client.containers.get(container_id)
        container.stop(timeout=10)
        logger.info("Stopped worker container %s", container_id[:12])
        return True
    except NotFound:
        logger.warning("Container %s not found (may have already exited)", container_id[:12])
        return False
    except APIError as exc:
        logger.error("Failed to stop container %s: %s", container_id[:12], exc)
        return False


async def get_worker_status(container_id: str) -> str | None:
    """Get the status of a worker container.

    Returns the container status string (e.g. "running", "exited") or None if not found.
    """
    client = _get_client()
    try:
        container = client.containers.get(container_id)
        return container.status
    except NotFound:
        return None


def _count_running_workers(client: docker.DockerClient) -> int:
    """Count currently running worker containers."""
    containers = client.containers.list(
        filters={
            "label": "cybersorted.role=worker",
            "status": "running",
        }
    )
    return len(containers)
