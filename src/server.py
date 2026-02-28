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

from src.auth.middleware import authenticate_request, AuthError
from src.core.config import settings
from src.core.usage import check_usage, record_usage
from src.tools.recon.passive import recon_passive

# --- MCP Server ---

mcp = FastMCP(
    "CyberSorted",
    instructions=(
        "CyberSorted MCP Server. Provides security tools including penetration testing, "
        "reconnaissance, and compliance assessments against authorised targets. "
        "Currently supports passive reconnaissance (free tier)."
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


# --- FastAPI App ---


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan — startup and shutdown."""
    yield


app = FastAPI(
    title="CyberSorted MCP",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "cybersorted-mcp",
        "environment": settings.ENVIRONMENT,
        "version": "0.1.0",
    }


@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.message})


# --- MCP Transport ---
# Mount the MCP server using Streamable HTTP transport on /mcp

mcp_app = mcp.streamable_http_app()
app.mount("/mcp", mcp_app)
