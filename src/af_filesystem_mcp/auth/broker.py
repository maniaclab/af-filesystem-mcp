"""Broker mode: per-user identity behind the AF MCP credential broker.

Unlike ami-mcp/rucio-mcp's broker mode, this backend never redeems an x509
proxy at the broker -- the bearer itself carries everything a filesystem
call needs: a broker-issued identity JWT whose ``uid``/``gid``/``unixname``
POSIX claims (af-mcp-platform's ``identityProviders[].targetOptions.
af-filesystem-mcp.includePosix: true``) are exactly the identity every
fs_* tool impersonates per call (see ``af_filesystem_mcp.impersonate``).

``af_credentials.mcp.mcp_token_verifier()`` adapts ``BrokerTokenVerifier`` to
the mcp SDK's ``TokenVerifier`` protocol for the authentication handshake,
but its adapter deliberately discards POSIX claims from the returned
``AccessToken`` (scopes stay empty by design -- see that module's own
docstring: "an MCP server wanting authorization must resolve it itself").
So this module keeps the same ``BrokerTokenVerifier`` instance around and
re-verifies the request's bearer a second time, per call, to recover
uid/gid/unixname -- cheap (the JWKS used for signature verification is
cached in-process by ``BrokerTokenVerifier`` itself) and avoids depending
on any out-of-band claim-propagation mechanism the mcp SDK does not
provide today.

Requires the ``broker`` extra: ``pip install af-filesystem-mcp[broker]``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

try:
    from af_credentials.mcp import mcp_token_verifier
    from af_credentials.verifier import BrokerTokenVerifier

    HAS_AF_CREDENTIALS = True
except ImportError:  # pragma: no cover - exercised only without the extra
    HAS_AF_CREDENTIALS = False

from af_filesystem_mcp.identity import Identity

if TYPE_CHECKING:
    from mcp.server.auth.provider import TokenVerifier

MISSING_AF_CREDENTIALS_MSG = (
    "broker mode requires the af-credentials package. "
    "Install it via the 'broker' extra: pip install af-filesystem-mcp[broker]"
)


class IdentityError(Exception):
    """Raised when a verified bearer carries no usable POSIX identity claims.

    This means the token itself is valid (correctly signed, right
    issuer/audience) but the broker's ``identityProviders`` entry for this
    backend was not configured with ``includePosix: true`` -- a deployment
    misconfiguration, not a caller error.
    """


def extract_bearer(ctx: Any) -> str:
    """Return the bearer token from the current request's Authorization header.

    The token has already been verified once by the server's
    ``TokenVerifier`` before any tool runs; this re-reads it so it can be
    verified a second time to recover its POSIX claims (see module
    docstring).

    Raises:
        PermissionError: If the header is missing or not a Bearer scheme.
    """
    auth = ctx.request_context.request.headers.get("authorization", "") or ""
    if not auth.lower().startswith("bearer "):
        msg = "Missing Bearer token in Authorization header"
        raise PermissionError(msg)
    return auth[7:].strip()


def make_broker_token_verifier(jwks_url: str, issuer: str, audience: str) -> Any:
    """Build the af_credentials verifier used for both the mcp handshake and per-call identity resolution."""
    if not HAS_AF_CREDENTIALS:
        raise ImportError(MISSING_AF_CREDENTIALS_MSG)
    return BrokerTokenVerifier(jwks_url, issuer, audience)


def make_mcp_token_verifier(verifier: Any) -> TokenVerifier:
    """Adapt *verifier* to the mcp SDK's ``TokenVerifier`` for the server's own auth handshake."""
    if not HAS_AF_CREDENTIALS:
        raise ImportError(MISSING_AF_CREDENTIALS_MSG)
    return mcp_token_verifier(verifier)


async def resolve_identity(ctx: Any, verifier: Any) -> Identity:
    """Re-verify the request's bearer against *verifier* and return its POSIX identity.

    Raises:
        PermissionError: no/malformed bearer (see ``extract_bearer``), or
            the bearer fails this second verification (should not happen —
            the mcp SDK already verified it once — but a JWKS key rotation
            landing mid-request is possible, and this is the same failure
            mode as any other auth rejection).
        IdentityError: the bearer verified but carries no uid/gid/unixname
            claims.
    """
    bearer = extract_bearer(ctx)
    claims = await verifier.verify(bearer)
    if claims is None:
        msg = "bearer failed re-verification"
        raise PermissionError(msg)
    if claims.uid is None or claims.gid is None or claims.unixname is None:
        msg = (
            "broker-issued token carries no uid/gid/unixname POSIX claims -- "
            "check the broker's identityProviders[].targetOptions."
            "af-filesystem-mcp.includePosix setting"
        )
        raise IdentityError(msg)
    return Identity(uid=claims.uid, gid=claims.gid, unixname=claims.unixname)
