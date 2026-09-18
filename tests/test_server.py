"""Tests for server construction: stdio and broker-mode HTTP transports."""

from __future__ import annotations

import logging
import os
import pwd
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from starlette.testclient import TestClient

from af_filesystem_mcp.server import (
    _configure_logging,
    _make_broker_app,
    _make_stdio_mcp,
)

if TYPE_CHECKING:
    from starlette.applications import Starlette

_JSON_RPC_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def _initialize_session(client: TestClient) -> dict[str, str]:
    """Do the MCP initialize handshake over *client* and return headers carrying the session id."""
    init_resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        },
        headers=_JSON_RPC_HEADERS,
    )
    session_id = init_resp.headers["mcp-session-id"]
    headers = {**_JSON_RPC_HEADERS, "mcp-session-id": session_id}
    client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers=headers,
    )
    return headers


class TestMakeStdioMcp:
    def test_registers_all_four_tools(self, tmp_path: Path) -> None:
        mcp = _make_stdio_mcp(data_root=tmp_path)
        names = {tool.name for tool in mcp._tool_manager.list_tools()}
        assert names == {"fs_list", "fs_stat", "fs_read", "fs_grep"}

    def test_every_tool_declares_annotations_and_output_schema(
        self, tmp_path: Path
    ) -> None:
        """Drift guard: every fs_* tool must publish read-only annotations and an outputSchema.

        This is the one test that would catch a future tool being added
        (or an existing one being refactored) without following the
        Annotated[CallToolResult, Model] + ToolAnnotations pattern all
        four tools use today -- see CLAUDE.md's "Tool registration
        pattern" section.
        """
        mcp = _make_stdio_mcp(data_root=tmp_path)
        for tool in mcp._tool_manager.list_tools():
            assert tool.annotations is not None, tool.name
            assert tool.annotations.read_only_hint is not None, tool.name
            assert tool.output_schema is not None, tool.name

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


class TestStdioAppOverTheWire:
    """Wire-level assertions that bypass every unit test's tool.fn shortcut.

    Every existing tool test calls the raw callable directly, which never
    goes through the mcp SDK's serialization -- none of them would notice
    a missing `annotations`/`outputSchema` on the wire. These do, via a
    real JSON-RPC round trip through the built ASGI app (see A.4/A.1 of
    the interop plan).
    """

    @pytest.fixture
    def app(self, tmp_path: Path) -> Any:
        data_root = tmp_path / "data"
        unixname = pwd.getpwuid(os.getuid()).pw_name
        (data_root / unixname).mkdir(parents=True)
        (data_root / unixname / "hello.txt").write_text("hi there")

        mcp = _make_stdio_mcp(data_root=data_root)
        return mcp.streamable_http_app(streamable_http_path="/mcp", json_response=True)

    @pytest.fixture
    def client(self, app: Any):
        with TestClient(app, base_url="http://127.0.0.1:8000") as test_client:
            yield test_client

    def test_tools_list_carries_annotations_and_output_schema(
        self, client: TestClient
    ) -> None:
        headers = _initialize_session(client)
        resp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            headers=headers,
        )
        assert resp.status_code == 200
        tools = {tool["name"]: tool for tool in resp.json()["result"]["tools"]}
        assert set(tools) == {"fs_list", "fs_stat", "fs_read", "fs_grep"}
        for tool in tools.values():
            assert tool["annotations"]["readOnlyHint"] is True
            assert tool["annotations"]["openWorldHint"] is False
            assert tool["outputSchema"] is not None

    def test_tools_call_carries_text_and_structured_content(
        self, client: TestClient
    ) -> None:
        headers = _initialize_session(client)
        resp = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "fs_list",
                    "arguments": {"root": "data", "path": ""},
                },
            },
            headers=headers,
        )
        assert resp.status_code == 200
        result = resp.json()["result"]
        assert result["isError"] is False
        assert result["content"][0]["type"] == "text"
        assert "hello.txt" in result["content"][0]["text"]
        structured = result["structuredContent"]
        assert structured["root"] == "data"
        assert structured["entries"][0]["name"] == "hello.txt"


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
