"""REST API router — APP-facing endpoints for scan management.

Endpoints:
    POST /api/v1/scans/start     — Start a new scan
    GET  /api/v1/scans/{id}/status — Get scan status and progress
    POST /api/v1/scans/{id}/cancel — Cancel a running scan
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src.api.internal_auth import InternalAuthError, authenticate_internal
from src.core.config import settings
from src.jobs.bridge import sync_to_security_scan
from src.jobs.dispatcher import DispatchError, launch_worker, stop_worker
from src.jobs.manager import create_job, fail_job, get_job, update_status
from src.jobs.models import JobConfig, JobSource, JobStatus, ScanLevel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scans")

# Background watcher tuning (mirrors the MCP tool's poll loop).
POLL_INTERVAL_SECONDS = 5
MAX_POLL_DURATION_SECONDS = 3600  # 1 hour


async def _watch_and_sync(job_id: str) -> None:
    """Poll a dispatched APP job to completion, bridging state to security-scans.

    The APP polls `companies/{id}/security-scans` directly — not this service —
    so without this watcher a completed worker's progress and final results would
    never reach the UI and the scan would appear to run forever. Syncs on every
    poll (for live progress) and once more on the terminal state.
    """
    elapsed = 0
    while elapsed < MAX_POLL_DURATION_SECONDS:
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
        elapsed += POLL_INTERVAL_SECONDS

        job = await get_job(job_id)
        if not job:
            logger.warning("Watcher: job %s disappeared before completion", job_id)
            return

        await sync_to_security_scan(job)

        if job.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
            logger.info(
                "Watcher: job %s reached %s — synced to security-scans",
                job_id, job.status.value,
            )
            return

    # Exceeded the hard timeout — mark failed and sync the terminal state.
    logger.warning(
        "Watcher: job %s exceeded %ss, marking failed", job_id, MAX_POLL_DURATION_SECONDS
    )
    await fail_job(job_id, "Scan timed out after 1 hour")
    timed_out = await get_job(job_id)
    if timed_out:
        await sync_to_security_scan(timed_out)


# --- Request/Response Models ---


class StartScanRequest(BaseModel):
    """Request body for POST /api/v1/scans/start."""

    company_id: str
    scan_id: str
    target_url: str
    scan_level: ScanLevel = ScanLevel.LIGHT
    firestore_project: str | None = None
    firestore_database: str | None = None


class StartScanResponse(BaseModel):
    """Response for POST /api/v1/scans/start."""

    job_id: str
    status: str = "queued"
    message: str = "Scan queued successfully"


class ScanStatusResponse(BaseModel):
    """Response for GET /api/v1/scans/{id}/status."""

    job_id: str
    status: str
    progress: dict = Field(default_factory=dict)
    results: dict | None = None
    error_message: str | None = None


class CancelResponse(BaseModel):
    """Response for POST /api/v1/scans/{id}/cancel."""

    job_id: str
    status: str
    message: str


# --- Error Handlers ---


async def _handle_auth(request: Request):
    """Authenticate internal request, raising appropriate HTTP errors."""
    try:
        return await authenticate_internal(request)
    except InternalAuthError as exc:
        raise exc


# --- Endpoints ---


@router.post("/start", response_model=StartScanResponse)
async def start_scan(request: Request, body: StartScanRequest):
    """Start a new security scan via the MCP worker infrastructure.

    Called by the APP's startSecurityScan() server action.
    """
    try:
        auth = await authenticate_internal(request)
    except InternalAuthError as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.message},
        )

    logger.info(
        "Scan requested by %s: company=%s, target=%s, level=%s",
        auth.service, body.company_id, body.target_url, body.scan_level,
    )

    # Create the pentest job
    config = JobConfig(
        target_url=body.target_url,
        scan_level=body.scan_level,
    )
    job = await create_job(
        source=JobSource.APP_SCANNER,
        config=config,
        container_image=settings.ZAP_WORKER_IMAGE,
        company_id=body.company_id,
        scan_id=body.scan_id,
        source_firestore_project=body.firestore_project,
        source_firestore_database=body.firestore_database,
    )

    # Dispatch the worker container
    try:
        container = await launch_worker(
            job_id=job.job_id,
            image=settings.ZAP_WORKER_IMAGE,
            env={
                "JOB_ID": job.job_id,
                "TARGET_URL": body.target_url,
                "SCAN_LEVEL": body.scan_level.value,
                "GCP_PROJECT": settings.GCP_PROJECT,
                "FIRESTORE_DATABASE": settings.FIRESTORE_DATABASE,
                "GOOGLE_APPLICATION_CREDENTIALS": settings.CREDENTIALS_PATH,
            },
        )
        await update_status(job.job_id, JobStatus.DISPATCHED, container_id=container.container_id)
        logger.info("Worker dispatched: %s → %s", job.job_id, container.container_id[:12])
    except DispatchError as exc:
        await fail_job(job.job_id, str(exc))
        # Sync failure to security-scans
        failed_job = await get_job(job.job_id)
        if failed_job:
            await sync_to_security_scan(failed_job)
        return JSONResponse(
            status_code=503,
            content={"error": str(exc), "job_id": job.job_id},
        )

    # Bridge job progress/results to security-scans in the background so the
    # APP UI (which polls security-scans, not this service) reflects completion.
    asyncio.create_task(_watch_and_sync(job.job_id))

    return StartScanResponse(job_id=job.job_id)


@router.get("/{job_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(request: Request, job_id: str):
    """Get the current status of a scan job.

    Called by the APP for progress polling (though the APP primarily polls
    security-scans directly — this endpoint is available as a fallback).
    """
    try:
        await authenticate_internal(request)
    except InternalAuthError as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.message},
        )

    job = await get_job(job_id)
    if not job:
        return JSONResponse(
            status_code=404,
            content={"error": f"Job {job_id} not found"},
        )

    # Sync to security-scans on each status check (lightweight bridging)
    await sync_to_security_scan(job)

    return ScanStatusResponse(
        job_id=job.job_id,
        status=job.status.value,
        progress=job.progress.model_dump(mode="json") if job.progress else {},
        results=job.results.model_dump(mode="json") if job.results else None,
        error_message=job.error_message,
    )


@router.post("/{job_id}/cancel", response_model=CancelResponse)
async def cancel_scan(request: Request, job_id: str):
    """Cancel a running scan.

    Stops the worker container and marks the job as cancelled.
    """
    try:
        await authenticate_internal(request)
    except InternalAuthError as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.message},
        )

    job = await get_job(job_id)
    if not job:
        return JSONResponse(
            status_code=404,
            content={"error": f"Job {job_id} not found"},
        )

    if job.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
        return CancelResponse(
            job_id=job_id,
            status=job.status.value,
            message=f"Job already {job.status.value}",
        )

    # Stop the container
    if job.container_id:
        await stop_worker(job.container_id)

    # Update status
    await update_status(job_id, JobStatus.CANCELLED)

    # Sync to security-scans
    cancelled_job = await get_job(job_id)
    if cancelled_job:
        await sync_to_security_scan(cancelled_job)

    return CancelResponse(
        job_id=job_id,
        status="cancelled",
        message="Scan cancelled successfully",
    )
