"""Firestore CRUD for pentest-jobs collection."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from google.cloud import firestore

from src.core.config import settings
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

logger = logging.getLogger(__name__)

COLLECTION = "pentest-jobs"


def _get_db() -> firestore.Client:
    """Get Firestore client for the configured database."""
    return firestore.Client(
        project=settings.GCP_PROJECT,
        database=settings.FIRESTORE_DATABASE,
    )


def _job_ref(db: firestore.Client, job_id: str) -> firestore.DocumentReference:
    """Get a document reference for a pentest job."""
    return db.collection(COLLECTION).document(job_id)


async def create_job(
    *,
    source: JobSource,
    config: JobConfig,
    container_image: str,
    tool: str = "scan_web_application",
    api_key_id: str | None = None,
    company_id: str | None = None,
    scan_id: str | None = None,
    source_firestore_project: str | None = None,
    source_firestore_database: str | None = None,
) -> PentestJob:
    """Create a new pentest job in Firestore.

    Returns the created PentestJob with its generated job_id.
    """
    job_id = str(uuid.uuid4())
    job = PentestJob(
        job_id=job_id,
        source=source,
        tool=tool,
        config=config,
        container_image=container_image,
        api_key_id=api_key_id,
        company_id=company_id,
        scan_id=scan_id,
        source_firestore_project=source_firestore_project,
        source_firestore_database=source_firestore_database,
    )

    db = _get_db()
    _job_ref(db, job_id).set(job.to_firestore())
    logger.info("Created job %s (source=%s, tool=%s)", job_id, source, tool)
    return job


async def get_job(job_id: str) -> PentestJob | None:
    """Fetch a job from Firestore. Returns None if not found."""
    db = _get_db()
    doc = _job_ref(db, job_id).get()
    if not doc.exists:
        return None
    return _doc_to_job(doc)


async def update_status(
    job_id: str,
    status: JobStatus,
    *,
    container_id: str | None = None,
    error_message: str | None = None,
) -> None:
    """Update job status and optional metadata."""
    db = _get_db()
    data: dict[str, Any] = {
        "status": status.value,
        "updated_at": firestore.SERVER_TIMESTAMP,
    }

    if status == JobStatus.DISPATCHED and container_id:
        data["container_id"] = container_id
    if status == JobStatus.RUNNING:
        data["started_at"] = datetime.now(timezone.utc)
    if status in (JobStatus.COMPLETED, JobStatus.FAILED):
        data["completed_at"] = datetime.now(timezone.utc)
    if error_message:
        data["error_message"] = error_message

    _job_ref(db, job_id).update(data)
    logger.info("Updated job %s → %s", job_id, status.value)


async def update_progress(job_id: str, progress: JobProgress) -> None:
    """Update the real-time progress of a running job."""
    db = _get_db()
    _job_ref(db, job_id).update({
        "progress": progress.model_dump(mode="json"),
        "updated_at": firestore.SERVER_TIMESTAMP,
    })


async def complete_job(
    job_id: str,
    *,
    results: ScanResults,
    alerts: list[ScanAlert],
    scan_stats: ScanStats | None = None,
) -> None:
    """Mark a job as completed with results."""
    db = _get_db()
    data: dict[str, Any] = {
        "status": JobStatus.COMPLETED.value,
        "results": results.model_dump(mode="json"),
        "alerts": [a.model_dump(mode="json") for a in alerts],
        "progress": JobProgress(
            phase="completed",
            spider_progress=100,
            active_scan_progress=100,
            message="Scan complete",
        ).model_dump(mode="json"),
        "completed_at": datetime.now(timezone.utc),
        "updated_at": firestore.SERVER_TIMESTAMP,
    }
    if scan_stats:
        data["scan_stats"] = scan_stats.model_dump(mode="json")

    _job_ref(db, job_id).update(data)
    logger.info("Completed job %s (high=%d, med=%d, low=%d)", job_id, results.high, results.medium, results.low)


async def fail_job(job_id: str, error_message: str) -> None:
    """Mark a job as failed with an error message."""
    await update_status(job_id, JobStatus.FAILED, error_message=error_message)


def _doc_to_job(doc: firestore.DocumentSnapshot) -> PentestJob:
    """Convert a Firestore document to a PentestJob model."""
    data = doc.to_dict()

    # Convert Firestore Timestamps to datetime
    for ts_field in ("created_at", "updated_at", "started_at", "completed_at"):
        val = data.get(ts_field)
        if val and hasattr(val, "timestamp"):
            data[ts_field] = datetime.fromtimestamp(val.timestamp(), tz=timezone.utc)

    # Reconstruct nested models
    if isinstance(data.get("config"), dict):
        data["config"] = JobConfig(**data["config"])
    if isinstance(data.get("progress"), dict):
        data["progress"] = JobProgress(**data["progress"])
    if isinstance(data.get("results"), dict):
        data["results"] = ScanResults(**data["results"])
    if isinstance(data.get("alerts"), list):
        data["alerts"] = [ScanAlert(**a) for a in data["alerts"]]
    if isinstance(data.get("scan_stats"), dict):
        data["scan_stats"] = ScanStats(**data["scan_stats"])

    return PentestJob(**data)
