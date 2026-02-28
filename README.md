# CyberSorted MCP Server

AI-powered security tools via any MCP client (Claude, Copilot, Cursor).

The AI provides the reasoning and decision-making; the MCP provides the hands -- real scanning, reconnaissance, and reporting tools executing against real targets.

## Sprint 1: Passive Recon (Free Tier)

This is the initial release with the `recon_passive` tool:

- **DNS records** -- A, AAAA, MX, TXT, CNAME, NS, SOA via dnspython
- **Subdomains** -- Certificate Transparency via crt.sh
- **WHOIS** -- RDAP lookup
- **Technologies** -- HTTP response header analysis
- **Certificates** -- CT log query results

No packets are sent to the target -- all data comes from DNS resolvers and public APIs.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Run locally
uvicorn src.server:app --reload --port 8080

# Health check
curl http://localhost:8080/health

# Run tests
python -m pytest tests/
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GCP_PROJECT` | GCP project ID | `cybersorted-dev` |
| `FIRESTORE_DATABASE` | Firestore database name | `database-uk-dev` |
| `STRIPE_SECRET_KEY` | Stripe secret key | -- |
| `ENVIRONMENT` | `dev` / `stage` / `prod` | `dev` |
| `PORT` | Server port | `8080` |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to GCP service account JSON | -- |

## Authentication

Requests require an API key via the `Authorization` header:

```
Authorization: Bearer cs_live_xxx
```

API keys are looked up in Firestore (`mcp-api-keys`) and validated against a Stripe subscription.

## Tiers

| Tier | Price | Passive Recon | Domains |
|------|-------|---------------|---------|
| Free | £0 | 5/month | 1 |
| Pro | £149/month | Unlimited | 5 |
| Enterprise | £399/month | Unlimited | Unlimited |

## Deployment (Azure VM)

The MCP server runs on an Azure VM (B2ms, UK South) with Docker Compose behind nginx with TLS.

### Architecture

```
MCP Client (Claude / Copilot / Cursor)
    │ MCP protocol (Streamable HTTP)
    │ Authorization: Bearer cs_live_xxx
    ▼
Azure VM (UK South): mcp.cybersorted.io
  nginx (TLS termination, rate limiting)
    │ reverse proxy
    ▼
  mcp-server (FastAPI + MCP SDK)
    │ Firestore (jobs, API keys, usage)
    │ GCS (reports, results)
    ▼
  GCP (cybersorted-prod)
```

### Prerequisites

1. Azure subscription with Terraform state storage configured
2. GCP service account with `roles/datastore.user` and `roles/storage.admin`
3. DNS A record for `mcp.cybersorted.io` pointing to the VM

### Provision the VM

```bash
# Copy and fill in variables
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# Edit terraform/terraform.tfvars with your values

# Provision infrastructure
cd terraform
terraform init
terraform plan
terraform apply
```

### Deploy the application

```bash
# SSH into the VM
ssh cybersorted@<vm-ip>

# Clone the repo
cd /app
git clone git@github.com:cyber-sorted/cybersorted-mcp.git .

# Copy GCP credentials and environment
scp gcp-sa-key.json cybersorted@<vm-ip>:/app/credentials/
cp .env.example .env
# Edit .env with production values

# Provision TLS certificate
sudo ./scripts/setup-tls.sh mcp.cybersorted.io admin@cybersorted.io

# Start services
docker compose up -d

# Verify
curl https://mcp.cybersorted.io/health
```

### GCP Service Account Setup

```bash
# Create service account
gcloud iam service-accounts create mcp-azure-vm \
  --project=cybersorted-prod \
  --display-name="MCP Azure VM"

# Grant Firestore access
gcloud projects add-iam-policy-binding cybersorted-prod \
  --member="serviceAccount:mcp-azure-vm@cybersorted-prod.iam.gserviceaccount.com" \
  --role="roles/datastore.user"

# Grant GCS access
gcloud projects add-iam-policy-binding cybersorted-prod \
  --member="serviceAccount:mcp-azure-vm@cybersorted-prod.iam.gserviceaccount.com" \
  --role="roles/storage.admin"

# Create and download key
gcloud iam service-accounts keys create gcp-sa-key.json \
  --iam-account=mcp-azure-vm@cybersorted-prod.iam.gserviceaccount.com
```

## Licence

Apache 2.0 -- see [LICENSE](LICENSE).
