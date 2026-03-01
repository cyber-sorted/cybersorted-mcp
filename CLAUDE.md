# CyberSorted MCP Server

## Overview

MCP server providing AI-powered security tools to any MCP client (Claude, Copilot, Cursor). Hosted on an Azure VM (B2ms, UK South) at `mcp.cybersorted.io`. Part of the CyberSorted platform.

**Version:** 0.2.0

Tool groups:
- **Pen testing** -- recon, scanning, exploitation, reporting
- **CISO advisory** -- security frameworks, policies, risk assessment (future)
- **CTO advisory** -- architecture review, tech health, cloud diagrams (future)

**Sprint 1:** Passive recon (`recon_passive`) — free tier, no workers.
**Sprint 2:** ZAP scanning (`scan_web_application`) — Docker worker dispatch, job system, REST API, APP bridge.

## Running Locally

```bash
pip install -e ".[dev]"
uvicorn src.server:app --reload --port 8080
```

## Environment Variables

- `GCP_PROJECT` -- GCP project ID (default: `cybersorted-dev`)
- `FIRESTORE_DATABASE` -- Firestore named database (default: `database-uk-dev`)
- `ENVIRONMENT` -- `dev` / `stage` / `prod` (default: `dev`)
- `PORT` -- Server port (default: `8080`)
- `GOOGLE_APPLICATION_CREDENTIALS` -- Path to GCP WIF config (Workload Identity Federation)
- `ZAP_WORKER_IMAGE` -- Docker image for ZAP worker (default: `cybersorted/zap-worker:latest`)
- `CREDENTIALS_PATH` -- Path to GCP WIF config for workers (default: `/app/credentials/gcp-wif-config.json`)
- `MAX_CONCURRENT_SCANS` -- Max simultaneous scan containers (default: `3`)

## Firestore Collections

- `mcp-api-keys/{key_hash}` -- API key records (tier, domains, created_at, active). Internal keys have `tier: "internal"`.
- `mcp-usage/{api_key_id}/monthly/{YYYY-MM}` -- Monthly usage counters per tool
- `pentest-jobs/{jobId}` -- Scan job records (status, progress, results, alerts). Created by MCP tool or REST API.

## Architecture

```
MCP Client (Claude / Copilot / Cursor)
    │ MCP protocol (Streamable HTTP)
    │ Authorization: Bearer cs_live_xxx
    ▼
APP (app.cybersorted.io)
    │ REST API (POST /api/v1/scans/start)
    │ Authorization: Bearer cs_internal_xxx
    ▼
Azure VM (UK South): mcp.cybersorted.io
  nginx (TLS + rate limiting + reverse proxy)
    ▼
  mcp-server container (FastAPI + MCP SDK + REST API)
    │ dispatches via Docker socket
    ▼
  zap-worker-{jobId} container (ephemeral, --rm)
    │ ZAP daemon + Python agent
    ▼
  GCP (cybersorted-prod): Firestore + GCS
```

## Key Files

| File | Purpose |
|------|---------|
| `src/server.py` | FastAPI app + MCP server (Streamable HTTP) + REST router |
| `src/auth/middleware.py` | API key validation, Stripe tier lookup |
| `src/tools/recon/passive.py` | `recon_passive` tool implementation |
| `src/tools/scanning/web_application.py` | `scan_web_application` MCP tool |
| `src/jobs/models.py` | Pydantic models: PentestJob, JobConfig, JobProgress |
| `src/jobs/manager.py` | Job CRUD: create, update, complete, fail |
| `src/jobs/dispatcher.py` | Docker SDK: launch/stop worker containers |
| `src/jobs/bridge.py` | Sync pentest-jobs → security-scans (APP-sourced jobs) |
| `src/api/router.py` | REST API: /api/v1/scans/{start,status,cancel} |
| `src/api/internal_auth.py` | Internal API key auth (cs_internal_ prefix) |
| `src/core/config.py` | Pydantic Settings configuration |
| `src/core/usage.py` | Usage tracking + tier limit enforcement |
| `workers/zap/Dockerfile` | ZAP worker container image |
| `workers/zap/agent.py` | Python agent: drives ZAP, writes progress to Firestore |
| `workers/zap/entrypoint.sh` | Start ZAP daemon, run agent |
| `docker-compose.yml` | nginx + mcp-server + Docker socket mount |
| `nginx/nginx.conf` | TLS termination, rate limiting, reverse proxy, /api/v1/ |
| `terraform/` | Azure VM infrastructure (Terraform) |
| `scripts/init-vm.sh` | Cloud-init: Docker, firewall, fail2ban |
| `scripts/setup-tls.sh` | Let's Encrypt certificate provisioning |

## REST API (Internal)

Used by the APP security scanner to dispatch scans via the MCP server.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/scans/start` | POST | Start a new scan (creates pentest-job + launches worker) |
| `/api/v1/scans/{job_id}/status` | GET | Poll scan progress and results |
| `/api/v1/scans/{job_id}/cancel` | POST | Cancel a running scan |

Auth: `Authorization: Bearer cs_internal_xxx` — key hash looked up in `mcp-api-keys` collection.

## Deployment

```bash
# SSH into VM
ssh -i ~/.ssh/id_ed25519 cybersorted@mcp.cybersorted.io

# Pull and rebuild
cd /app
sudo git pull origin main
docker compose build mcp-server
docker compose up -d

# Build ZAP worker image (only when workers/zap/ changes)
sudo docker build -t cybersorted/zap-worker:latest workers/zap/
```

## Full Design

See `docs/PENTEST-MCP-PLAN.md` in the platform repo (`cybersorted-platform`) for the pen testing implementation plan covering all 10 MCP tools, worker containers, and reporting.

## Language

Use UK English in all user-facing text, documentation, and comments.

## Testing

```bash
python -m pytest tests/  # 77 tests (Sprint 2)
```

## Status

- **Sprint 0+1:** Complete — passive recon, auth, metering, 13 tests
- **Sprint 2:** Complete — ZAP worker, Docker dispatch, job system, REST API, APP bridge, 77 tests, deployed v0.2.0
- **Known issue:** Azure WIF auth has tenant mismatch (`upbeatdata.com` vs correct tenant) — needs Azure AD app registration fix
- **Next:** Sprint 3 (recon_active + scan_infrastructure — Nmap/Nuclei workers), integration testing
