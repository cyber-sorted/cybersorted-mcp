"""Pydantic models for the pentest-jobs system."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    """Lifecycle states for a pentest job."""

    QUEUED = "queued"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobSource(str, Enum):
    """Where the job originated."""

    MCP = "mcp"
    APP_SCANNER = "app-scanner"


class ScanLevel(str, Enum):
    """Scan intensity level."""

    LIGHT = "light"
    DEEP = "deep"
    AGGRESSIVE = "aggressive"


class JobConfig(BaseModel):
    """Configuration for a scan job."""

    target_url: str
    scan_level: ScanLevel = ScanLevel.LIGHT
    scope: str | None = None
    policy: str | None = None


class JobProgress(BaseModel):
    """Real-time progress for a running job."""

    phase: str = "queued"
    spider_progress: int = Field(default=0, ge=0, le=100)
    active_scan_progress: int = Field(default=0, ge=0, le=100)
    message: str = ""


class ScanAlert(BaseModel):
    """A single vulnerability finding from the scan."""

    name: str
    severity: str  # High, Medium, Low, Informational
    url: str = ""
    description: str = ""
    solution: str = ""
    cweid: str = ""
    wascid: str = ""
    confidence: str = ""
    reference: str = ""


class ScanResults(BaseModel):
    """Summary results from a completed scan."""

    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    score: int = 100


class ScanStats(BaseModel):
    """Operational statistics from the scan run."""

    urls_crawled: int = 0
    requests_sent: int = 0
    duration_seconds: int = 0


class PentestJob(BaseModel):
    """Full pentest job document stored in Firestore pentest-jobs/{jobId}."""

    job_id: str
    source: JobSource
    tool: str = "scan_web_application"
    status: JobStatus = JobStatus.QUEUED

    # Source identifiers
    api_key_id: str | None = None  # MCP-sourced jobs
    company_id: str | None = None  # APP-sourced jobs
    scan_id: str | None = None  # Links to security-scans doc (APP only)

    # APP source Firestore coordinates (for bridge sync)
    source_firestore_project: str | None = None
    source_firestore_database: str | None = None

    # Configuration
    config: JobConfig

    # Progress
    progress: JobProgress = Field(default_factory=JobProgress)

    # Results (populated on completion)
    results: ScanResults | None = None
    alerts: list[ScanAlert] = Field(default_factory=list)
    scan_stats: ScanStats | None = None

    # Error
    error_message: str | None = None

    # Container
    container_id: str | None = None
    container_image: str = ""

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None

    def to_firestore(self) -> dict[str, Any]:
        """Serialise to Firestore-compatible dict (no None values)."""
        from google.cloud.firestore import SERVER_TIMESTAMP

        data = self.model_dump(mode="json")
        # Replace timestamps with server timestamps where appropriate
        data["updated_at"] = SERVER_TIMESTAMP
        if self.status == JobStatus.QUEUED and self.created_at:
            data["created_at"] = SERVER_TIMESTAMP
        # Strip None values — Firestore doesn't allow undefined
        return {k: v for k, v in data.items() if v is not None}
