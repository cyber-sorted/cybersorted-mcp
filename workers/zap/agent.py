"""ZAP Worker Agent — drives OWASP ZAP and writes results to Firestore.

Python port of apps/scanner/src/index.ts from the cybersorted-platform repo.
Runs inside the zap-worker container alongside the ZAP daemon.

Environment Variables:
    JOB_ID: Pentest job ID (pentest-jobs/{jobId})
    TARGET_URL: URL to scan
    SCAN_LEVEL: light, deep, or aggressive
    GCP_PROJECT: GCP project ID
    FIRESTORE_DATABASE: Firestore database name
    ZAP_API_KEY: ZAP API key (default: cybersorted-scanner-key)
    ZAP_HOST: ZAP proxy host (default: localhost)
    ZAP_PORT: ZAP proxy port (default: 8080)
    GOOGLE_APPLICATION_CREDENTIALS: Path to GCP credentials
"""

from __future__ import annotations

import logging
import math
import os
import sys
import time
from datetime import datetime, timezone

import httpx
from google.cloud import firestore

# --- Configuration ---

JOB_ID = os.environ.get("JOB_ID")
TARGET_URL = os.environ.get("TARGET_URL")
SCAN_LEVEL = os.environ.get("SCAN_LEVEL", "light").lower()
GCP_PROJECT = os.environ.get("GCP_PROJECT", "cybersorted-dev")
FIRESTORE_DATABASE = os.environ.get("FIRESTORE_DATABASE", "database-uk-dev")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "cybersorted-scanner-key")
ZAP_HOST = os.environ.get("ZAP_HOST", "localhost")
ZAP_PORT = os.environ.get("ZAP_PORT", "8080")
ZAP_API_URL = f"http://{ZAP_HOST}:{ZAP_PORT}"

COLLECTION = "pentest-jobs"

# Scan policy per level
THREAD_COUNT = {"light": 2, "deep": 5, "aggressive": 10}
MAX_DURATION_MINS = {"light": 10, "deep": 30, "aggressive": 0}  # 0 = unlimited
MAX_CHILDREN = {"light": 10, "deep": 50, "aggressive": 100}

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
logger = logging.getLogger("zap-agent")


# --- Firestore ---

def get_db() -> firestore.Client:
    return firestore.Client(project=GCP_PROJECT, database=FIRESTORE_DATABASE)


def job_ref(db: firestore.Client) -> firestore.DocumentReference:
    return db.collection(COLLECTION).document(JOB_ID)


def update_job(db: firestore.Client, data: dict) -> None:
    """Update the pentest-jobs document with progress/results."""
    data["updated_at"] = firestore.SERVER_TIMESTAMP
    try:
        job_ref(db).update(data)
    except Exception:
        logger.exception("Failed to update job %s", JOB_ID)


# --- ZAP API ---

def zap_api(client: httpx.Client, endpoint: str, params: dict | None = None) -> dict:
    """Call the ZAP JSON API."""
    url = f"{ZAP_API_URL}/JSON/{endpoint}"
    all_params = {"apikey": ZAP_API_KEY}
    if params:
        all_params.update(params)

    resp = client.get(url, params=all_params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def wait_for_zap(client: httpx.Client, max_attempts: int = 30) -> None:
    """Wait for ZAP daemon to be ready (up to 60s)."""
    logger.info("Waiting for ZAP daemon...")
    for i in range(max_attempts):
        try:
            zap_api(client, "core/view/version")
            logger.info("ZAP is ready!")
            return
        except Exception:
            logger.info("Attempt %d/%d...", i + 1, max_attempts)
            time.sleep(2)
    raise RuntimeError("ZAP failed to start within timeout")


# --- Scan Phases ---

def configure_policy(client: httpx.Client) -> None:
    """Configure ZAP scan policy based on scan level."""
    logger.info("Configuring %s scan policy...", SCAN_LEVEL)

    try:
        zap_api(client, "ascan/action/setOptionThreadPerHost", {
            "Integer": str(THREAD_COUNT.get(SCAN_LEVEL, 2)),
        })
        logger.info("Thread count: %d", THREAD_COUNT.get(SCAN_LEVEL, 2))
    except Exception:
        logger.info("Could not set thread count, using defaults")

    try:
        zap_api(client, "ascan/action/setOptionMaxScanDurationInMins", {
            "Integer": str(MAX_DURATION_MINS.get(SCAN_LEVEL, 10)),
        })
        logger.info("Max duration: %d mins", MAX_DURATION_MINS.get(SCAN_LEVEL, 10))
    except Exception:
        logger.info("Could not set scan duration, using defaults")


def run_spider(client: httpx.Client, db: firestore.Client) -> None:
    """Run ZAP spider to discover pages."""
    logger.info("Starting spider scan...")
    update_job(db, {
        "status": "running",
        "progress": {
            "phase": "crawling",
            "spider_progress": 0,
            "active_scan_progress": 0,
            "message": "Discovering pages...",
        },
    })

    resp = zap_api(client, "spider/action/scan", {
        "url": TARGET_URL,
        "maxChildren": str(MAX_CHILDREN.get(SCAN_LEVEL, 10)),
        "recurse": "true",
        "subtreeOnly": "true",
    })
    spider_id = resp.get("scan", "0")
    logger.info("Spider started (id=%s)", spider_id)

    progress = 0
    while progress < 100:
        time.sleep(3)
        status_resp = zap_api(client, "spider/view/status", {"scanId": spider_id})
        progress = int(status_resp.get("status", "0"))
        logger.info("Spider progress: %d%%", progress)
        update_job(db, {
            "progress": {
                "phase": "crawling",
                "spider_progress": progress,
                "active_scan_progress": 0,
                "message": f"Discovering pages... {progress}%",
            },
        })

    logger.info("Spider scan completed")


def wait_for_passive_scan(client: httpx.Client, db: firestore.Client) -> None:
    """Wait for passive scan to finish analysing spider results."""
    logger.info("Waiting for passive scan...")
    update_job(db, {
        "progress": {
            "phase": "scanning",
            "spider_progress": 100,
            "active_scan_progress": 0,
            "message": "Passive analysis...",
        },
    })

    last_progress = 0
    while True:
        time.sleep(2)
        try:
            resp = zap_api(client, "pscan/view/recordsToScan")
            remaining = int(resp.get("recordsToScan", "0"))
            if remaining == 0:
                break
            progress = min(95, 100 - remaining)
            if progress != last_progress:
                logger.info("Passive scan: %d records remaining", remaining)
                update_job(db, {
                    "progress": {
                        "phase": "scanning",
                        "spider_progress": 100,
                        "active_scan_progress": progress,
                        "message": f"Passive analysis... {remaining} records remaining",
                    },
                })
                last_progress = progress
        except Exception:
            logger.info("Could not check passive scan, assuming complete")
            break

    update_job(db, {
        "progress": {
            "phase": "scanning",
            "spider_progress": 100,
            "active_scan_progress": 100,
            "message": "Passive analysis complete",
        },
    })
    logger.info("Passive scan completed")


def run_active_scan(client: httpx.Client, db: firestore.Client) -> None:
    """Run ZAP active vulnerability scan (deep/aggressive only)."""
    logger.info("Starting active scan...")
    update_job(db, {
        "progress": {
            "phase": "scanning",
            "spider_progress": 100,
            "active_scan_progress": 0,
            "message": "Active vulnerability scanning...",
        },
    })

    resp = zap_api(client, "ascan/action/scan", {
        "url": TARGET_URL,
        "recurse": "true",
        "inScopeOnly": "false",
    })
    scan_id = resp.get("scan", "0")
    logger.info("Active scan started (id=%s)", scan_id)

    progress = 0
    while progress < 100:
        time.sleep(5)
        status_resp = zap_api(client, "ascan/view/status", {"scanId": scan_id})
        progress = int(status_resp.get("status", "0"))
        logger.info("Active scan progress: %d%%", progress)
        update_job(db, {
            "progress": {
                "phase": "scanning",
                "spider_progress": 100,
                "active_scan_progress": progress,
                "message": f"Active scanning... {progress}%",
            },
        })

    logger.info("Active scan completed")


def get_results(client: httpx.Client) -> tuple[dict, list[dict]]:
    """Fetch scan results from ZAP and calculate score."""
    logger.info("Fetching scan results...")

    resp = zap_api(client, "core/view/alerts", {
        "baseurl": TARGET_URL or "",
        "start": "0",
        "count": "1000",
    })
    raw_alerts = resp.get("alerts", [])

    # Count by severity
    high = medium = low = informational = 0
    alerts = []

    for alert in raw_alerts:
        risk = (alert.get("risk") or "Informational").lower()
        if risk == "high":
            high += 1
        elif risk == "medium":
            medium += 1
        elif risk == "low":
            low += 1
        else:
            informational += 1

        alerts.append({
            "name": alert.get("alert", alert.get("name", "")),
            "severity": alert.get("risk", "Informational"),
            "confidence": alert.get("confidence", ""),
            "url": alert.get("url", ""),
            "description": alert.get("description", ""),
            "solution": alert.get("solution", ""),
            "reference": alert.get("reference", ""),
            "cweid": alert.get("cweid", ""),
            "wascid": alert.get("wascid", ""),
        })

    # Score: 100 = clean, 0 = critical
    raw_score = 100 - (high * 10 + medium * 5 + low * 2 + informational * 0.5)
    score = max(0, round(raw_score))

    results = {
        "high": high,
        "medium": medium,
        "low": low,
        "informational": informational,
        "score": score,
    }

    logger.info(
        "Results: High=%d Medium=%d Low=%d Info=%d Score=%d/100",
        high, medium, low, informational, score,
    )
    return results, alerts


# --- Main ---

def main() -> None:
    if not JOB_ID or not TARGET_URL:
        logger.error("Missing required env vars: JOB_ID=%s, TARGET_URL=%s", JOB_ID, TARGET_URL)
        sys.exit(1)

    logger.info("=" * 50)
    logger.info("CyberSorted ZAP Worker Agent")
    logger.info("Job: %s", JOB_ID)
    logger.info("Target: %s", TARGET_URL)
    logger.info("Level: %s", SCAN_LEVEL)
    logger.info("=" * 50)

    db = get_db()
    http_client = httpx.Client()
    start_time = time.time()

    try:
        # Mark as running
        update_job(db, {
            "status": "running",
            "started_at": datetime.now(timezone.utc),
            "progress": {
                "phase": "starting",
                "spider_progress": 0,
                "active_scan_progress": 0,
                "message": "Initialising scanner...",
            },
        })

        # Wait for ZAP daemon
        wait_for_zap(http_client)

        # Configure scan policy
        configure_policy(http_client)

        # Set up context (optional — scan works without it)
        try:
            zap_api(http_client, "context/action/newContext", {"contextName": "ScanContext"})
            zap_api(http_client, "context/action/includeInContext", {
                "contextName": "ScanContext",
                "regex": f"{TARGET_URL}.*",
            })
            logger.info("Context configured")
        except Exception:
            logger.info("Could not configure context, proceeding without it")

        # Spider scan (discovers pages)
        run_spider(http_client, db)

        # Light = passive only, Deep/Aggressive = active scan
        if SCAN_LEVEL == "light":
            logger.info("Light scan: passive analysis only")
            wait_for_passive_scan(http_client, db)
        else:
            logger.info("%s scan: running active vulnerability scan", SCAN_LEVEL.title())
            run_active_scan(http_client, db)

        # Fetch results
        results, alerts = get_results(http_client)

        # Calculate scan stats
        duration = int(time.time() - start_time)
        scan_stats = {
            "urls_crawled": 0,
            "requests_sent": 0,
            "duration_seconds": duration,
        }

        # Try to get URL count from ZAP
        try:
            msgs_resp = zap_api(http_client, "core/view/numberOfMessages")
            scan_stats["requests_sent"] = int(msgs_resp.get("numberOfMessages", 0))
        except Exception:
            pass
        try:
            urls_resp = zap_api(http_client, "core/view/urls")
            scan_stats["urls_crawled"] = len(urls_resp.get("urls", []))
        except Exception:
            pass

        # Write final results
        update_job(db, {
            "status": "completed",
            "results": results,
            "alerts": alerts,
            "scan_stats": scan_stats,
            "completed_at": datetime.now(timezone.utc),
            "progress": {
                "phase": "completed",
                "spider_progress": 100,
                "active_scan_progress": 100,
                "message": "Scan complete",
            },
        })

        logger.info("=" * 50)
        logger.info("Scan completed successfully!")
        logger.info("Score: %d/100 | Duration: %ds", results["score"], duration)
        logger.info("=" * 50)

    except Exception as exc:
        logger.exception("Scan failed")
        try:
            update_job(db, {
                "status": "failed",
                "error_message": str(exc),
                "completed_at": datetime.now(timezone.utc),
                "progress": {
                    "phase": "failed",
                    "spider_progress": 0,
                    "active_scan_progress": 0,
                    "message": f"Failed: {exc}",
                },
            })
        except Exception:
            logger.exception("Failed to write error status")
        sys.exit(1)
    finally:
        http_client.close()


if __name__ == "__main__":
    main()
