"""The resolved caller identity every filesystem tool call impersonates."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Identity:
    """A caller's real POSIX identity: the exact uid/gid a filesystem call impersonates.

    Built either from a broker-issued token's POSIX claims (broker/HTTP
    mode, see ``af_filesystem_mcp.auth.broker``) or from the server
    process's own identity (stdio/local mode, see
    ``af_filesystem_mcp.auth.local``) -- callers downstream (the tools
    layer, ``af_filesystem_mcp.impersonate``) never need to know which.
    """

    uid: int
    gid: int
    unixname: str
