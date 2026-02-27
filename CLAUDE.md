# CyberSorted MCP Server

## Overview

MCP server providing AI-powered security tools to any MCP client (Claude, Copilot, Cursor). Hosted on Cloud Run at `mcp.cybersorted.io`. Part of the CyberSorted platform.

Tool groups:
- **Pen testing** -- recon, scanning, exploitation, reporting (Sprint 1+)
- **CISO advisory** -- security frameworks, policies, risk assessment (future)
- **CTO advisory** -- architecture review, tech health, cloud diagrams (future)

**Sprint 1 scope:** Passive recon only (free tier). No Cloud Run Jobs or workers yet.

## Running Locally

```bash
pip install -e ".[dev]"
uvicorn src.server:app --reload --port 8080
```

## Environment Variables

- `GCP_PROJECT` -- GCP project ID (default: `cybersorted-dev`)
- `FIRESTORE_DATABASE` -- Firestore named database (default: `database-uk-dev`)
- `STRIPE_SECRET_KEY` -- Stripe secret key for subscription validation
- `ENVIRONMENT` -- `dev` / `stage` / `prod` (default: `dev`)
- `PORT` -- Server port (default: `8080`)

## Firestore Collections

- `mcp-api-keys/{key_hash}` -- API key records (tier, stripe_customer_id, stripe_subscription_id, domains, created_at, active)
- `mcp-usage/{api_key_id}/monthly/{YYYY-MM}` -- Monthly usage counters per tool

## Architecture

```
MCP Client (Claude / Copilot / Cursor)
    | MCP protocol (Streamable HTTP)
    | Authorization: Bearer cs_live_xxx
    v
Cloud Run Service: mcp.cybersorted.io
  - FastAPI + MCP SDK (FastMCP)
  - Auth middleware (API key -> Firestore -> Stripe)
  - Usage tracking + limit enforcement
  - Tools: recon_passive (Sprint 1)
```

## Key Files

| File | Purpose |
|------|---------|
| `src/server.py` | FastAPI app + MCP server (Streamable HTTP) |
| `src/auth/middleware.py` | API key validation, Stripe tier lookup |
| `src/tools/recon/passive.py` | `recon_passive` tool implementation |
| `src/core/config.py` | Pydantic Settings configuration |
| `src/core/usage.py` | Usage tracking + tier limit enforcement |

## Full Design

See `docs/PENTEST-MCP-PLAN.md` in the platform repo (`cybersorted-platform`) for the pen testing implementation plan covering all 10 MCP tools, worker containers, and reporting.

## Language

Use UK English in all user-facing text, documentation, and comments.

## Testing

```bash
python -m pytest tests/
```

## Deployment

```bash
gcloud builds submit --config=cloudbuild.yaml \
  --project=cybersorted-dev \
  --substitutions=_ENVIRONMENT=dev
```
