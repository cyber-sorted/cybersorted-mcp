"""Pipeline API router — ICP pipeline stage execution.

Endpoints:
    POST /api/v1/pipeline/run     — Run a pipeline stage
    GET  /api/v1/pipeline/status  — Get pipeline status
"""

from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from google.cloud import firestore
from pydantic import BaseModel

from src.api.internal_auth import authenticate_internal, InternalAuthError
from src.core.config import settings
from src.pipeline.companies_house import import_companies
from src.pipeline.scorer import score_batch

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/pipeline")

# Firestore client (lazy init)
_db: firestore.Client | None = None


def _get_db() -> firestore.Client:
    global _db
    if _db is None:
        _db = firestore.Client(
            project=settings.GCP_PROJECT,
            database=settings.FIRESTORE_DATABASE,
        )
    return _db


PIPELINE_COMPANIES = "pipeline/data/companies"
PIPELINE_STATS = "pipeline/data/stats"
PIPELINE_RUNS = "pipeline/data/runs"
CRM_COMPANIES = "crm/data/companies"


class PipelineRunRequest(BaseModel):
    """Request body for POST /api/v1/pipeline/run."""
    stage: str  # companies_house, enrich, score, sync
    triggered_by: str = "system"
    search_queries: list[str] | None = None


class PipelineRunResponse(BaseModel):
    """Response for POST /api/v1/pipeline/run."""
    stage: str
    status: str
    processed: int = 0
    message: str = ""


VALID_STAGES = {"companies_house", "enrich", "score", "sync"}


@router.post("/run", response_model=PipelineRunResponse)
async def run_pipeline_stage(request: Request, body: PipelineRunRequest):
    """Run a pipeline stage.

    Stages:
    - companies_house: Import companies from Companies House API
    - enrich: Add missing data (SIC codes, officers) — not yet implemented
    - score: Compute ICP scores for all pipeline companies
    - sync: Sync high-scoring companies to CRM
    """
    try:
        await authenticate_internal(request)
    except InternalAuthError as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.message},
        )

    if body.stage not in VALID_STAGES:
        return JSONResponse(
            status_code=400,
            content={"error": f"Invalid stage. Must be one of: {', '.join(VALID_STAGES)}"},
        )

    logger.info("Pipeline stage '%s' triggered by %s", body.stage, body.triggered_by)

    db = _get_db()
    run_id = f"{body.stage}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

    try:
        if body.stage == "companies_house":
            result = await _stage_companies_house(db, body.search_queries)
        elif body.stage == "enrich":
            result = await _stage_enrich(db)
        elif body.stage == "score":
            result = await _stage_score(db)
        elif body.stage == "sync":
            result = await _stage_sync(db)
        else:
            result = {"processed": 0, "message": "Unknown stage"}

        # Log the run
        db.collection(PIPELINE_RUNS).document(run_id).set({
            "stage": body.stage,
            "status": "completed",
            "triggered_by": body.triggered_by,
            "processed": result.get("processed", 0),
            "message": result.get("message", ""),
            "completed_at": firestore.SERVER_TIMESTAMP,
        })

        return PipelineRunResponse(
            stage=body.stage,
            status="completed",
            processed=result.get("processed", 0),
            message=result.get("message", ""),
        )

    except Exception as exc:
        logger.error("Pipeline stage '%s' failed: %s", body.stage, exc)

        db.collection(PIPELINE_RUNS).document(run_id).set({
            "stage": body.stage,
            "status": "failed",
            "triggered_by": body.triggered_by,
            "error": str(exc),
            "completed_at": firestore.SERVER_TIMESTAMP,
        })

        return JSONResponse(
            status_code=500,
            content={"error": f"Pipeline stage failed: {exc}"},
        )


async def _stage_companies_house(
    db: firestore.Client,
    search_queries: list[str] | None = None,
) -> dict:
    """Import companies from Companies House."""
    companies = await import_companies(search_queries or [])

    batch = db.batch()
    for company in companies:
        cn = company.get("company_number")
        if not cn:
            continue
        ref = db.collection(PIPELINE_COMPANIES).document(cn)
        batch.set(ref, {
            **company,
            "source": "companies_house",
            "imported_at": firestore.SERVER_TIMESTAMP,
            "icp_score": None,
            "crm_synced": False,
        }, merge=True)

    batch.commit()

    return {
        "processed": len(companies),
        "message": f"Imported {len(companies)} companies from Companies House",
    }


async def _stage_enrich(db: firestore.Client) -> dict:
    """Enrich pipeline companies with additional data."""
    # Fetch companies missing SIC codes or officer data
    docs = db.collection(PIPELINE_COMPANIES).limit(50).stream()
    enriched = 0

    for doc in docs:
        data = doc.to_dict()
        if data.get("sic_codes"):
            continue

        # Fetch full profile from Companies House
        from src.pipeline.companies_house import get_company_profile, get_officers

        cn = doc.id
        profile = await get_company_profile(cn)
        if profile:
            officers = await get_officers(cn)
            doc.reference.update({
                "sic_codes": profile.get("sic_codes", []),
                "officer_count": len(officers),
                "enriched_at": firestore.SERVER_TIMESTAMP,
            })
            enriched += 1

    return {
        "processed": enriched,
        "message": f"Enriched {enriched} companies",
    }


async def _stage_score(db: firestore.Client) -> dict:
    """Score all pipeline companies against ICP criteria."""
    docs = list(db.collection(PIPELINE_COMPANIES).stream())
    companies = [{"id": doc.id, **doc.to_dict()} for doc in docs]

    scored = score_batch(companies)

    batch = db.batch()
    for company in scored:
        ref = db.collection(PIPELINE_COMPANIES).document(company["id"])
        batch.update(ref, {
            "icp_score": company.get("icp_score", 0),
            "icp_factors": company.get("icp_factors", {}),
            "scored_at": firestore.SERVER_TIMESTAMP,
        })

    batch.commit()

    # Update stats
    score_dist = {"hot": 0, "warm": 0, "nurture": 0, "discard": 0}
    for c in scored:
        s = c.get("icp_score", 0)
        if s >= 80:
            score_dist["hot"] += 1
        elif s >= 60:
            score_dist["warm"] += 1
        elif s >= 40:
            score_dist["nurture"] += 1
        else:
            score_dist["discard"] += 1

    db.collection(PIPELINE_STATS).document("latest").set({
        "total_companies": len(scored),
        "score_distribution": score_dist,
        "last_scored_at": firestore.SERVER_TIMESTAMP,
    })

    return {
        "processed": len(scored),
        "message": f"Scored {len(scored)} companies — {score_dist}",
    }


async def _stage_sync(db: firestore.Client) -> dict:
    """Sync high-scoring pipeline companies to CRM."""
    # Get companies with score >= 60 that haven't been synced
    docs = (
        db.collection(PIPELINE_COMPANIES)
        .where("icp_score", ">=", 60)
        .where("crm_synced", "==", False)
        .stream()
    )

    synced = 0
    batch = db.batch()

    for doc in docs:
        data = doc.to_dict()
        company_name = data.get("company_name", "Unknown")
        company_number = doc.id

        # Create CRM company
        crm_ref = db.collection(CRM_COMPANIES).document()
        batch.set(crm_ref, {
            "name": company_name,
            "domain": None,
            "industry": None,
            "companySize": None,
            "leadSource": "pipeline",
            "leadScore": data.get("icp_score", 0),
            "marketingStatus": "lead",
            "salesStatus": None,
            "customerStatus": None,
            "touchCount": 0,
            "companiesHouseNumber": company_number,
            "createdAt": firestore.SERVER_TIMESTAMP,
            "createdBy": "bot@cybersorted.io",
        })

        # Mark as synced
        batch.update(doc.reference, {
            "crm_synced": True,
            "crm_company_id": crm_ref.id,
            "synced_at": firestore.SERVER_TIMESTAMP,
        })

        synced += 1

    if synced > 0:
        batch.commit()

    return {
        "processed": synced,
        "message": f"Synced {synced} companies to CRM",
    }


@router.get("/status")
async def get_pipeline_status(request: Request):
    """Get pipeline status and stats."""
    try:
        await authenticate_internal(request)
    except InternalAuthError as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.message},
        )

    db = _get_db()

    # Get latest stats
    stats_doc = db.collection(PIPELINE_STATS).document("latest").get()
    stats = stats_doc.to_dict() if stats_doc.exists else {}

    # Get recent runs
    runs = []
    for doc in db.collection(PIPELINE_RUNS).order_by("completed_at", direction="DESCENDING").limit(10).stream():
        run_data = doc.to_dict()
        runs.append({
            "id": doc.id,
            "stage": run_data.get("stage"),
            "status": run_data.get("status"),
            "processed": run_data.get("processed", 0),
            "triggered_by": run_data.get("triggered_by"),
            "message": run_data.get("message"),
        })

    return {
        "stats": stats,
        "recent_runs": runs,
    }
