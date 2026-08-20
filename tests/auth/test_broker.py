"""Tests for broker-mode identity resolution: bearer extraction + POSIX claim recovery.

af_credentials.mcp's adapter strips POSIX claims out of the mcp SDK's
AccessToken by design (see af_filesystem_mcp.auth.broker's module
docstring), so resolve_identity re-verifies the bearer itself against a
BrokerTokenVerifier-shaped object. These tests use a small duck-typed fake
(matching BrokerClaims' uid/gid/unixname attributes) rather than the real
af_credentials.verifier.BrokerTokenVerifier, keeping this suite decoupled
from that package's own (already-tested) JWKS/JWT internals.
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest

from af_filesystem_mcp.auth import broker
from af_filesystem_mcp.auth.broker import (
    IdentityError,
    extract_bearer,
    resolve_identity,
)


def _make_ctx(headers: dict[str, str]) -> MagicMock:
    ctx = MagicMock()
    ctx.request_context.request.headers = headers
    return ctx


@dataclass
class _FakeClaims:
    sub: str = "test-sub"
    jti: str = "test-jti"
    exp: int = 0
    uid: int | None = 4321
    gid: int | None = 8765
    unixname: str | None = "alice"


class _FakeVerifier:
    def __init__(self, claims: _FakeClaims | None) -> None:
        self._claims = claims
        self.seen_tokens: list[str] = []

    async def verify(self, token: str) -> _FakeClaims | None:
        self.seen_tokens.append(token)
        return self._claims


class TestExtractBearer:
    def test_returns_token(self) -> None:
        ctx = _make_ctx({"authorization": "Bearer abc123"})
        assert extract_bearer(ctx) == "abc123"

    def test_case_insensitive_scheme(self) -> None:
        ctx = _make_ctx({"authorization": "bearer abc123"})
        assert extract_bearer(ctx) == "abc123"

    def test_missing_header_raises_permission_error(self) -> None:
        ctx = _make_ctx({})
        with pytest.raises(PermissionError):
            extract_bearer(ctx)

    def test_non_bearer_scheme_raises_permission_error(self) -> None:
        ctx = _make_ctx({"authorization": "Basic abc123"})
        with pytest.raises(PermissionError):
            extract_bearer(ctx)


class TestResolveIdentity:
    async def test_returns_identity_from_claims(self) -> None:
        ctx = _make_ctx({"authorization": "Bearer abc123"})
        verifier = _FakeVerifier(_FakeClaims(uid=4321, gid=8765, unixname="alice"))

        identity = await resolve_identity(ctx, verifier)

        assert identity.uid == 4321
        assert identity.gid == 8765
        assert identity.unixname == "alice"
        assert verifier.seen_tokens == ["abc123"]

    async def test_missing_bearer_raises_permission_error(self) -> None:
        ctx = _make_ctx({})
        verifier = _FakeVerifier(_FakeClaims())
        with pytest.raises(PermissionError):
            await resolve_identity(ctx, verifier)

    async def test_failed_reverification_raises_permission_error(self) -> None:
        ctx = _make_ctx({"authorization": "Bearer abc123"})
        verifier = _FakeVerifier(None)
        with pytest.raises(PermissionError):
            await resolve_identity(ctx, verifier)

    async def test_missing_posix_claims_raises_identity_error(self) -> None:
        ctx = _make_ctx({"authorization": "Bearer abc123"})
        verifier = _FakeVerifier(_FakeClaims(uid=None, gid=None, unixname=None))
        with pytest.raises(IdentityError, match="includePosix"):
            await resolve_identity(ctx, verifier)

    async def test_partial_posix_claims_raises_identity_error(self) -> None:
        ctx = _make_ctx({"authorization": "Bearer abc123"})
        verifier = _FakeVerifier(_FakeClaims(uid=4321, gid=None, unixname="alice"))
        with pytest.raises(IdentityError):
            await resolve_identity(ctx, verifier)


class TestModuleImportGuard:
    def test_has_af_credentials_is_true_in_this_test_environment(self) -> None:
        # This suite installs the `broker` extra, so the real af_credentials
        # import at module load time must have succeeded -- if this is
        # False, make_broker_token_verifier/make_mcp_token_verifier's
        # ImportError guard would be masking a real packaging problem here.
        assert broker.HAS_AF_CREDENTIALS is True
