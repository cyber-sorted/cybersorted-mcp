"""scan_web_application MCP tool — dispatches a ZAP scan and returns results.

For external MCP clients (Claude, Copilot, Cursor). Creates a pentest job,
dispatches the ZAP worker container, polls for completion, and returns
structured vulnerability results.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from src.core.config import settings
from src.jobs.dispatcher import DispatchError, launch_worker
from src.jobs.manager import create_job, fail_job, get_job, update_status
from src.jobs.models import JobConfig, JobSource, JobStatus, ScanLevel

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 5
MAX_POLL_DURATION_SECONDS = 3600  # 1 hour


async def scan_web_application(
    *,
    target_url: str,
    scan_level: str = "light",
    scope: str | None = None,
    policy: str | None = None,
    api_key_id: str | None = None,
) -> dict[str, Any]:
    """Run a web application vulnerability scan using OWASP ZAP.

    Launches a ZAP worker container, runs spider + passive/active scanning
    against the target URL, and returns structured vulnerability findings.

    Args:
        target_url: The URL to scan (e.g. "https://example.com").
        scan_level: Intensity — "light" (passive only, ~5-10 min),
                    "deep" (active scan, ~30-60 min), or
                    "aggressive" (full active scan, unlimited time).
        scope: Optional regex to restrict scan scope.
        policy: Optional scan policy name.
        api_key_id: MCP API key hash (set by the MCP server).

    Returns:
        Dictionary with scan results including vulnerabilities, score, and stats.
    """
    # Validate scan level
    try:
        level = ScanLevel(scan_level.lower())
    except ValueError:
        return {"error": f"Invalid scan_level: {scan_level}. Use light, deep, or aggressive."}

    config = JobConfig(
        target_url=target_url,
        scan_level=level,
        scope=scope,
        policy=policy,
    )

    # Create job
    job = await create_job(
        source=JobSource.MCP,
        config=config,
        container_image=settings.ZAP_WORKER_IMAGE,
        api_key_id=api_key_id,
    )

    # Dispatch worker
    try:
        container = await launch_worker(
            job_id=job.job_id,
            image=settings.ZAP_WORKER_IMAGE,
            env={
                "JOB_ID": job.job_id,
                "TARGET_URL": target_url,
                "SCAN_LEVEL": level.value,
                "GCP_PROJECT": settings.GCP_PROJECT,
                "FIRESTORE_DATABASE": settings.FIRESTORE_DATABASE,
                "GOOGLE_APPLICATION_CREDENTIALS": settings.CREDENTIALS_PATH,
            },
        )
        await update_status(job.job_id, JobStatus.DISPATCHED, container_id=container.container_id)
    except DispatchError as exc:
        await fail_job(job.job_id, str(exc))
        return {
            "error": str(exc),
            "job_id": job.job_id,
            "status": "failed",
        }

    # Poll for completion
    logger.info("Polling job %s for completion...", job.job_id)
    elapsed = 0

    while elapsed < MAX_POLL_DURATION_SECONDS:
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
        elapsed += POLL_INTERVAL_SECONDS

        current = await get_job(job.job_id)
        if not current:
            return {"error": "Job disappeared", "job_id": job.job_id}

        if current.status == JobStatus.COMPLETED:
            return _format_results(current)

        if current.status in (JobStatus.FAILED, JobStatus.CANCELLED):
            return {
                "error": current.error_message or f"Scan {current.status.value}",
                "job_id": job.job_id,
                "status": current.status.value,
            }

        # Log progress periodically
        if elapsed % 30 == 0 and current.progress:
            logger.info(
                "Job %s: %s (spider=%d%%, active=%d%%)",
                job.job_id, current.progress.phase,
                current.progress.spider_progress,
                current.progress.active_scan_progress,
            )

    # Timeout
    await fail_job(job.job_id, "Scan timed out after 1 hour")
    return {
        "error": "Scan timed out after 1 hour",
        "job_id": job.job_id,
        "status": "failed",
    }


def _format_results(job) -> dict[str, Any]:
    """Format completed job results for MCP client consumption."""
    result: dict[str, Any] = {
        "job_id": job.job_id,
        "status": "completed",
        "target_url": job.config.target_url,
        "scan_level": job.config.scan_level.value,
    }

    if job.results:
        result["summary"] = {
            "high": job.results.high,
            "medium": job.results.medium,
            "low": job.results.low,
            "informational": job.results.informational,
            "security_score": job.results.score,
        }

    if job.alerts:
        result["vulnerabilities"] = [
            {
                "name": a.name,
                "severity": a.severity,
                "url": a.url,
                "description": a.description,
                "solution": a.solution,
                "cwe_id": a.cweid,
                "wasc_id": a.wascid,
            }
            for a in job.alerts
        ]
        result["vulnerability_count"] = len(job.alerts)

    if job.scan_stats:
        result["stats"] = {
            "urls_crawled": job.scan_stats.urls_crawled,
            "requests_sent": job.scan_stats.requests_sent,
            "duration_seconds": job.scan_stats.duration_seconds,
        }

    return result
