"""Bridge: sync pentest-jobs progress/results → security-scans (APP-sourced jobs only).

When the APP dispatches a scan via the REST API, it creates both:
  - security-scans/{scanId} in companies/{companyId}/security-scans (for the APP UI)
  - pentest-jobs/{jobId} (for the worker)

This bridge syncs status, progress, and results from pentest-jobs back to
security-scans so the APP UI can poll a single collection.
"""

from __future__ import annotations

import logging
from typing import Any

from google.cloud import firestore

from src.core.config import settings
from src.jobs.models import JobStatus, PentestJob

logger = logging.getLogger(__name__)

# Map pentest-jobs status → security-scans status
_STATUS_MAP: dict[str, str] = {
    "queued": "pending",
    "dispatched": "pending",
    "running": "scanning",
    "completed": "completed",
    "failed": "failed",
    "cancelled": "failed",
}

# Map progress phase → security-scans status (more granular)
_PHASE_STATUS_MAP: dict[str, str] = {
    "queued": "pending",
    "starting": "pending",
    "crawling": "crawling",
    "scanning": "scanning",
    "completed": "completed",
    "failed": "failed",
}


def _get_bridge_db(job: PentestJob) -> firestore.Client:
    """Get Firestore client for the APP's database (where security-scans live)."""
    project = job.source_firestore_project or settings.GCP_PROJECT
    database = job.source_firestore_database or settings.FIRESTORE_DATABASE
    return firestore.Client(project=project, database=database)


async def sync_to_security_scan(job: PentestJob) -> None:
    """Sync a pentest job's state to its linked security-scans document.

    Only applies to APP-sourced jobs (source == "app-scanner") that have
    both a company_id and scan_id set.
    """
    if not job.company_id or not job.scan_id:
        return

    db = _get_bridge_db(job)
    scan_ref = (
        db.collection("companies")
        .document(job.company_id)
        .collection("security-scans")
        .document(job.scan_id)
    )

    data: dict[str, Any] = {
        "updatedAt": firestore.SERVER_TIMESTAMP,
    }

    # Status — use phase-based mapping for more granularity
    phase = job.progress.phase if job.progress else "queued"
    if phase in _PHASE_STATUS_MAP:
        data["status"] = _PHASE_STATUS_MAP[phase]
    else:
        data["status"] = _STATUS_MAP.get(job.status.value, "pending")

    # Override with terminal statuses
    if job.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
        data["status"] = _STATUS_MAP[job.status.value]

    # Progress
    if job.progress:
        data["spiderProgress"] = job.progress.spider_progress
        data["activeScanProgress"] = job.progress.active_scan_progress

    # Results (on completion)
    if job.status == JobStatus.COMPLETED and job.results:
        data["results"] = {
            "high": job.results.high,
            "medium": job.results.medium,
            "low": job.results.low,
            "informational": job.results.informational,
            "score": job.results.score,
        }
        data["completedAt"] = firestore.SERVER_TIMESTAMP

    # Alerts (on completion)
    if job.status == JobStatus.COMPLETED and job.alerts:
        data["alerts"] = [
            {
                "alert": a.name,
                "risk": a.severity,
                "confidence": a.confidence,
                "url": a.url,
                "description": a.description,
                "solution": a.solution,
                "reference": a.reference,
                "cweid": a.cweid,
                "wascid": a.wascid,
            }
            for a in job.alerts
        ]

    # Error
    if job.error_message:
        data["errorMessage"] = job.error_message

    try:
        scan_ref.update(data)
        logger.debug(
            "Synced job %s → security-scans/%s (status=%s)",
            job.job_id, job.scan_id, data.get("status"),
        )
    except Exception:
        logger.exception(
            "Failed to sync job %s → security-scans/%s",
            job.job_id, job.scan_id,
        )
