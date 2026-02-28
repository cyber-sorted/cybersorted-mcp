# CyberSorted MCP Server

## Overview

MCP server providing AI-powered security tools to any MCP client (Claude, Copilot, Cursor). Hosted on an Azure VM (B2ms, UK South) at `mcp.cybersorted.io`. Part of the CyberSorted platform.

Tool groups:
- **Pen testing** -- recon, scanning, exploitation, reporting (Sprint 1+)
- **CISO advisory** -- security frameworks, policies, risk assessment (future)
- **CTO advisory** -- architecture review, tech health, cloud diagrams (future)

**Sprint 1 scope:** Passive recon only (free tier). No worker containers yet.

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
- `GOOGLE_APPLICATION_CREDENTIALS` -- Path to GCP service account JSON key

## Firestore Collections

- `mcp-api-keys/{key_hash}` -- API key records (tier, stripe_customer_id, stripe_subscription_id, domains, created_at, active)
- `mcp-usage/{api_key_id}/monthly/{YYYY-MM}` -- Monthly usage counters per tool

## Architecture

```
MCP Client (Claude / Copilot / Cursor)
    │ MCP protocol (Streamable HTTP)
    │ Authorization: Bearer cs_live_xxx
    ▼
Azure VM (UK South): mcp.cybersorted.io
  nginx (TLS + rate limiting + reverse proxy)
    ▼
  mcp-server container (FastAPI + MCP SDK)
    │
    ▼
  GCP (cybersorted-prod): Firestore + GCS
```

## Infrastructure

| Component | Technology |
|-----------|-----------|
| VM | Azure B2ms (2 vCPU, 8 GB RAM), Ubuntu 24.04 LTS |
| Region | UK South |
| IaC | Terraform (`terraform/`) |
| Container orchestration | Docker Compose |
| TLS | Let's Encrypt via certbot |
| Reverse proxy | nginx |
| Backend data | GCP Firestore + GCS (via service account key) |

## Key Files

| File | Purpose |
|------|---------|
| `src/server.py` | FastAPI app + MCP server (Streamable HTTP) |
| `src/auth/middleware.py` | API key validation, Stripe tier lookup |
| `src/tools/recon/passive.py` | `recon_passive` tool implementation |
| `src/core/config.py` | Pydantic Settings configuration |
| `src/core/usage.py` | Usage tracking + tier limit enforcement |
| `docker-compose.yml` | nginx + mcp-server container orchestration |
| `nginx/nginx.conf` | TLS termination, rate limiting, reverse proxy |
| `terraform/` | Azure VM infrastructure (Terraform) |
| `scripts/init-vm.sh` | Cloud-init: Docker, firewall, fail2ban |
| `scripts/setup-tls.sh` | Let's Encrypt certificate provisioning |

## Deployment

```bash
# Provision Azure VM
cd terraform && terraform init && terraform plan && terraform apply

# SSH into VM and deploy
ssh cybersorted@<vm-ip>
cd /app
git clone git@github.com:cyber-sorted/cybersorted-mcp.git .
cp .env.example .env  # Edit with production values
sudo ./scripts/setup-tls.sh
docker compose up -d
```

## Full Design

See `docs/PENTEST-MCP-PLAN.md` in the platform repo (`cybersorted-platform`) for the pen testing implementation plan covering all 10 MCP tools, worker containers, and reporting.

## Language

Use UK English in all user-facing text, documentation, and comments.

## Testing

```bash
python -m pytest tests/
```
