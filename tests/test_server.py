"""Tests for server construction: stdio and broker-mode HTTP transports."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from starlette.testclient import TestClient

from af_filesystem_mcp.server import (
    _configure_logging,
    _make_broker_app,
    _make_stdio_mcp,
)

if TYPE_CHECKING:
    from starlette.applications import Starlette


class TestMakeStdioMcp:
    def test_registers_all_four_tools(self, tmp_path: Path) -> None:
        mcp = _make_stdio_mcp(data_root=tmp_path)
        names = {tool.name for tool in mcp._tool_manager.list_tools()}
        assert names == {"fs_list", "fs_stat", "fs_read", "fs_grep"}

    async def test_lifespan_yields_local_identity_resolver_and_roots(
        self, tmp_path: Path
    ) -> None:
        mcp = _make_stdio_mcp(data_root=tmp_path)
        assert mcp.settings.lifespan is not None
        async with mcp.settings.lifespan(mcp) as ctx_dict:
            identity = await ctx_dict["identity_resolver"](None)
            assert identity.unixname
            assert ctx_dict["roots_config"].data_root == tmp_path
            assert ctx_dict["roots_config"].home_root == Path("/home")


@pytest.fixture
def broker_app() -> Starlette:
    return _make_broker_app(
        jwks_url="https://broker.example.com/.well-known/jwks.json",
        issuer="https://broker.example.com",
        audience="af-filesystem-mcp",
        home_root=Path("/home"),
        data_root=Path("/data"),
        timeout_seconds=10.0,
        max_concurrent_calls_per_user=4,
        resource_url="http://localhost:8000",
        host="127.0.0.1",
    )


@pytest.fixture
def broker_client(broker_app: Starlette):
    with TestClient(
        broker_app, base_url="http://127.0.0.1:8000", raise_server_exceptions=True
    ) as test_client:
        yield test_client


class TestMakeBrokerApp:
    def test_healthz_needs_no_auth(self, broker_client: TestClient) -> None:
        resp = broker_client.get("/healthz")
        assert resp.status_code == 200
        assert "ok" in resp.text.lower()

    def test_mcp_endpoint_without_auth_is_rejected(
        self, broker_client: TestClient
    ) -> None:
        resp = broker_client.post("/mcp", json={})
        assert resp.status_code in (401, 400)


class TestConfigureLogging:
    @pytest.fixture(autouse=True)
    def _restore_root_level(self):
        root = logging.getLogger()
        original = root.level
        yield
        root.setLevel(original)

    def test_debug_enables_library_debug_logging(self) -> None:
        _configure_logging("debug")
        assert logging.getLogger("af_credentials.verifier").isEnabledFor(logging.DEBUG)

    def test_info_does_not_enable_debug(self) -> None:
        _configure_logging("info")
        verifier = logging.getLogger("af_credentials.verifier")
        assert not verifier.isEnabledFor(logging.DEBUG)
        assert verifier.isEnabledFor(logging.INFO)
