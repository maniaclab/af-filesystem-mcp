"""Command-line interface for af-filesystem-mcp."""

from __future__ import annotations

import argparse
import os

from af_filesystem_mcp.server import serve


def main() -> None:
    """Entry point for the af-filesystem-mcp command."""
    parser = argparse.ArgumentParser(
        prog="af-filesystem-mcp",
        description="MCP server for per-user, impersonated filesystem access on the AF platform",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    serve_parser = subparsers.add_parser(
        "serve",
        help="Start the MCP server",
    )
    serve_parser.add_argument(
        "--transport",
        choices=("stdio", "http"),
        default="stdio",
        help="Transport to serve on (default: stdio)",
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address for HTTP transport (default: 127.0.0.1)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for HTTP transport (default: 8000)",
    )
    serve_parser.add_argument(
        "--home-root",
        default=os.environ.get("AF_FILESYSTEM_MCP_HOME_ROOT", "/home"),
        help=(
            "Root prefix your NFS home lives under; your own root is "
            "<home-root>/<unixname> (env: AF_FILESYSTEM_MCP_HOME_ROOT; "
            "default: /home). Ignored (uses your real $HOME) in stdio mode."
        ),
    )
    serve_parser.add_argument(
        "--data-root",
        default=os.environ.get("AF_FILESYSTEM_MCP_DATA_ROOT", "/data"),
        help=(
            "Root prefix your Ceph data area lives under; your own root is "
            "<data-root>/<unixname> (env: AF_FILESYSTEM_MCP_DATA_ROOT; "
            "default: /data)"
        ),
    )
    serve_parser.add_argument(
        "--resource-url",
        default=os.environ.get("AF_FILESYSTEM_MCP_RESOURCE_URL"),
        help=(
            "Externally visible base URL of this server "
            "(env: AF_FILESYSTEM_MCP_RESOURCE_URL; default: http://HOST:PORT)"
        ),
    )
    serve_parser.add_argument(
        "--broker-url",
        default=os.environ.get("AF_FILESYSTEM_MCP_BROKER_URL"),
        help=(
            "AF credential broker base URL. HTTP transport is broker-only "
            "for this backend -- there is no shared-secret mode, since a "
            "single shared identity would defeat per-user impersonation "
            "(env: AF_FILESYSTEM_MCP_BROKER_URL)"
        ),
    )
    serve_parser.add_argument(
        "--broker-jwks-url",
        default=os.environ.get("AF_FILESYSTEM_MCP_BROKER_JWKS_URL"),
        help=(
            "JWKS URL for verifying broker-issued JWTs "
            "(env: AF_FILESYSTEM_MCP_BROKER_JWKS_URL; "
            "default: BROKER_URL/.well-known/jwks.json)"
        ),
    )
    serve_parser.add_argument(
        "--broker-issuer",
        default=os.environ.get("AF_FILESYSTEM_MCP_BROKER_ISSUER"),
        help=(
            "Expected iss claim of broker-issued JWTs "
            "(env: AF_FILESYSTEM_MCP_BROKER_ISSUER; default: BROKER_URL)"
        ),
    )
    serve_parser.add_argument(
        "--broker-audience",
        default=os.environ.get(
            "AF_FILESYSTEM_MCP_BROKER_AUDIENCE", "af-filesystem-mcp"
        ),
        help=(
            "Expected aud claim of broker-issued JWTs "
            "(env: AF_FILESYSTEM_MCP_BROKER_AUDIENCE; default: af-filesystem-mcp)"
        ),
    )
    serve_parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=float(os.environ.get("AF_FILESYSTEM_MCP_TIMEOUT_SECONDS", "10.0")),
        help="Wall-clock budget per filesystem call before it is killed (default: 10.0)",
    )
    serve_parser.add_argument(
        "--max-concurrent-calls-per-user",
        type=int,
        default=int(
            os.environ.get("AF_FILESYSTEM_MCP_MAX_CONCURRENT_CALLS_PER_USER", "4")
        ),
        help="Per-user concurrency cap on in-flight filesystem calls (default: 4)",
    )
    serve_parser.add_argument(
        "--forwarded-allow-ips",
        default="127.0.0.1",
        help="IPs trusted for X-Forwarded-* headers (default: 127.0.0.1)",
    )
    serve_parser.add_argument(
        "--log-level",
        default="info",
        help="uvicorn log level for HTTP transport (default: info)",
    )

    args = parser.parse_args()

    if args.command == "serve":
        serve(
            transport=args.transport,
            host=args.host,
            port=args.port,
            home_root=args.home_root,
            data_root=args.data_root,
            resource_url=args.resource_url,
            broker_url=args.broker_url,
            broker_jwks_url=args.broker_jwks_url,
            broker_issuer=args.broker_issuer,
            broker_audience=args.broker_audience,
            timeout_seconds=args.timeout_seconds,
            max_concurrent_calls_per_user=args.max_concurrent_calls_per_user,
            forwarded_allow_ips=args.forwarded_allow_ips,
            log_level=args.log_level,
        )
    else:
        parser.print_help()
