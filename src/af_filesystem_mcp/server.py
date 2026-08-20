"""MCP server setup for af-filesystem-mcp.

Two transports, and unlike ami-mcp/rucio-mcp there is no "shared-secret"
HTTP mode here: a shared secret would mean one shared service identity
impersonating a single fixed uid for every caller, which defeats the
entire point of this backend (per-user impersonation). HTTP transport is
broker-only.

- stdio: exactly one caller -- the process's own uid/gid (see
  ``af_filesystem_mcp.auth.local``). No impersonation happens or is
  needed; every fs_* call is confined to that identity's own ``$HOME``
  and a configured local data root.
- http (broker mode): bearers are broker-issued identity JWTs carrying
  ``uid``/``gid``/``unixname`` POSIX claims (af-mcp-platform's
  ``identityProviders[].targetOptions.af-filesystem-mcp.includePosix:
  true``); every call re-verifies the bearer to recover those claims (see
  ``af_filesystem_mcp.auth.broker``) and impersonates that identity for
  exactly one filesystem operation.
"""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

import uvicorn
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.mcpserver import MCPServer
from pydantic import AnyHttpUrl
from starlette.responses import JSONResponse

from af_filesystem_mcp.auth.broker import (
    make_broker_token_verifier,
    make_mcp_token_verifier,
)
from af_filesystem_mcp.auth.broker import resolve_identity as broker_resolve_identity
from af_filesystem_mcp.auth.local import local_identity
from af_filesystem_mcp.roots import RootsConfig
from af_filesystem_mcp.tools import grep_files, list_dir, read_file, stat_path

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from starlette.applications import Starlette
    from starlette.requests import Request

_INSTRUCTIONS = (
    "MCP server for browsing and reading your own files on the AF (Analysis "
    "Facility): your NFS home (/home/<you>) and Ceph data area "
    "(/data/<you>). Every operation is confined to those two roots and runs "
    "impersonating your real identity -- nothing here can read or list "
    "another user's files. This is a read-only server: there is no write, "
    "delete, rename, or command-execution tool of any kind.\n\n"
    "Tools: fs_list (browse a directory), fs_stat (metadata for one path), "
    "fs_read (read a file, by byte range or line range / head / tail), "
    "fs_grep (search file contents under a directory, recursive, capped)."
)


def _register_all(mcp: MCPServer) -> None:
    """Register every tool module on *mcp*."""
    for _module in [list_dir, stat_path, read_file, grep_files]:
        _module.register(mcp)


def _make_stdio_mcp(*, data_root: Path) -> MCPServer:
    """Build the stdio-transport server: single caller, the process's own identity."""

    async def _identity_resolver(_ctx: Any) -> Any:
        return local_identity()

    @asynccontextmanager
    async def _lifespan(_server: MCPServer) -> AsyncGenerator[dict[str, Any], None]:
        yield {
            "identity_resolver": _identity_resolver,
            "roots_config": RootsConfig(home_root=Path("/home"), data_root=data_root),
        }

    mcp = MCPServer("af-filesystem-mcp", lifespan=_lifespan, instructions=_INSTRUCTIONS)
    _register_all(mcp)
    return mcp


def _make_broker_app(
    *,
    jwks_url: str,
    issuer: str,
    audience: str,
    home_root: Path,
    data_root: Path,
    timeout_seconds: float,
    max_concurrent_calls_per_user: int,
    resource_url: str,
    host: str,
) -> Starlette:
    """Build the ASGI app for HTTP transport behind the AF credential broker."""
    verifier = make_broker_token_verifier(jwks_url, issuer, audience)
    mcp_verifier = make_mcp_token_verifier(verifier)

    async def _identity_resolver(ctx: Any) -> Any:
        return await broker_resolve_identity(ctx, verifier)

    @asynccontextmanager
    async def _lifespan(_server: MCPServer) -> AsyncGenerator[dict[str, Any], None]:
        yield {
            "identity_resolver": _identity_resolver,
            "roots_config": RootsConfig(home_root=home_root, data_root=data_root),
            "timeout_seconds": timeout_seconds,
            "max_concurrent_calls_per_user": max_concurrent_calls_per_user,
        }

    mcp = MCPServer(
        "af-filesystem-mcp",
        instructions=_INSTRUCTIONS,
        lifespan=_lifespan,
        token_verifier=mcp_verifier,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(resource_url),
            # The aggregator injects the bearer itself; there is no OAuth
            # discovery chain to advertise on this resource.
            resource_server_url=None,
            client_registration_options=ClientRegistrationOptions(enabled=False),
            required_scopes=[],
        ),
    )
    _register_all(mcp)

    async def _healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    mcp.custom_route("/healthz", methods=["GET"])(_healthz)

    return mcp.streamable_http_app(streamable_http_path="/mcp", host=host)


def _configure_logging(log_level: str) -> None:
    """Apply the CLI log level to the root logger (HTTP transport only, see serve())."""
    logging.basicConfig(
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger().setLevel(log_level.upper())


def serve(
    transport: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 8000,
    data_root: str = "/data",
    home_root: str = "/home",
    resource_url: str | None = None,
    broker_url: str | None = None,
    broker_jwks_url: str | None = None,
    broker_issuer: str | None = None,
    broker_audience: str = "af-filesystem-mcp",
    timeout_seconds: float = 10.0,
    max_concurrent_calls_per_user: int = 4,
    forwarded_allow_ips: str = "127.0.0.1",
    log_level: str = "info",
) -> None:
    """Start the MCP server over the selected transport."""
    if transport == "stdio":
        _make_stdio_mcp(data_root=Path(data_root)).run(transport="stdio")
        return

    if not broker_url:
        sys.stderr.write(
            "[af-filesystem-mcp] Error: --transport http requires --broker-url "
            "(or AF_FILESYSTEM_MCP_BROKER_URL). HTTP transport is broker-only "
            "-- there is no shared-secret mode for this backend.\n"
        )
        sys.exit(1)

    app = _make_broker_app(
        jwks_url=broker_jwks_url or f"{broker_url.rstrip('/')}/.well-known/jwks.json",
        issuer=broker_issuer or broker_url,
        audience=broker_audience,
        home_root=Path(home_root),
        data_root=Path(data_root),
        timeout_seconds=timeout_seconds,
        max_concurrent_calls_per_user=max_concurrent_calls_per_user,
        resource_url=resource_url or f"http://{host}:{port}",
        host=host,
    )

    _configure_logging(log_level)
    uvicorn.run(
        app,
        host=host,
        port=port,
        proxy_headers=True,
        forwarded_allow_ips=forwarded_allow_ips,
        log_level=log_level,
    )
