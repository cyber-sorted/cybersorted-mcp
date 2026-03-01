"""CyberSorted MCP Server.

Streamable HTTP transport via FastAPI, serving security tools
to any MCP client (Claude, Copilot, Cursor).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mcp.server.fastmcp import FastMCP

from src.api.internal_auth import InternalAuthError
from src.api.router import router as scans_router
from src.auth.middleware import AuthError
from src.core.config import settings
from src.tools.recon.passive import recon_passive
from src.tools.scanning.web_application import scan_web_application

# --- MCP Server ---

mcp = FastMCP(
    "CyberSorted",
    instructions=(
        "CyberSorted MCP Server. Provides security tools including penetration testing, "
        "reconnaissance, and vulnerability scanning against authorised targets. "
        "Supports passive reconnaissance (free tier) and web application scanning (pro+)."
    ),
)


@mcp.tool()
async def recon_passive_tool(target: str, depth: str = "standard") -> dict:
    """Run passive reconnaissance against a target domain.

    Gathers DNS records, subdomains (via Certificate Transparency), WHOIS data,
    technology fingerprints, and certificate information. No packets are sent to
    the target — all data comes from DNS resolvers and public APIs.

    Args:
        target: Domain to investigate (e.g. "example.com")
        depth: "standard" for quick scan, "deep" for thorough enumeration
    """
    return await recon_passive(target=target, depth=depth)


@mcp.tool()
async def scan_web_application_tool(
    target_url: str,
    scan_level: str = "light",
    scope: str | None = None,
    policy: str | None = None,
) -> dict:
    """Run a web application vulnerability scan using OWASP ZAP.

    Launches a security scanner against the target URL to discover
    vulnerabilities. Returns structured findings with severity ratings,
    descriptions, and remediation guidance.

    Scan levels:
    - "light": Spider + passive analysis only (~5-10 minutes). No active probing.
    - "deep": Spider + active vulnerability scanning (~30-60 minutes).
    - "aggressive": Full active scan with no time limit.

    Args:
        target_url: The URL to scan (e.g. "https://example.com")
        scan_level: Scan intensity — "light", "deep", or "aggressive"
        scope: Optional regex to restrict scan scope
        policy: Optional scan policy name
    """
    return await scan_web_application(
        target_url=target_url,
        scan_level=scan_level,
        scope=scope,
        policy=policy,
    )


# --- FastAPI App ---


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan — startup and shutdown."""
    yield


app = FastAPI(
    title="CyberSorted MCP",
    version="0.2.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "cybersorted-mcp",
        "environment": settings.ENVIRONMENT,
        "version": "0.2.0",
    }


@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.message})


@app.exception_handler(InternalAuthError)
async def internal_auth_error_handler(request: Request, exc: InternalAuthError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.message})


# --- REST API ---
# APP-facing endpoints for scan dispatch and status

app.include_router(scans_router)


# --- MCP Transport ---
# Mount the MCP server using Streamable HTTP transport on /mcp

mcp_app = mcp.streamable_http_app()
app.mount("/mcp", mcp_app)
