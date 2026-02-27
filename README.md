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

## Authentication

Requests require an API key via the `Authorization` header:

```
Authorization: Bearer cs_live_xxx
```

API keys are looked up in Firestore (`mcp-api-keys`) and validated against a Stripe subscription.

## Tiers

| Tier | Price | Passive Recon | Domains |
|------|-------|---------------|---------|
| Free | GBP 0 | 5/month | 1 |
| Pro | GBP 149/month | Unlimited | 5 |
| Enterprise | GBP 399/month | Unlimited | Unlimited |

## Deployment

Deployed to Cloud Run via Cloud Build:

```bash
gcloud builds submit --config=cloudbuild.yaml \
  --project=cybersorted-dev \
  --substitutions=_ENVIRONMENT=dev
```

## Licence

Apache 2.0 -- see [LICENSE](LICENSE).
