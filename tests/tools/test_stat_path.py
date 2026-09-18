"""Tests for fs_stat."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from mcp.server.mcpserver import MCPServer

from af_filesystem_mcp.tools.stat_path import register

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path
    from unittest.mock import MagicMock

    from mcp.types import CallToolResult


@pytest.fixture
def fs_stat_tool() -> Any:
    mcp = MCPServer("test")
    register(mcp)
    return next(
        tool for tool in mcp._tool_manager.list_tools() if tool.name == "fs_stat"
    )


@pytest.fixture
def fs_stat(fs_stat_tool: Any) -> Callable[..., Awaitable[CallToolResult]]:
    return fs_stat_tool.fn  # type: ignore[no-any-return]


class TestFsStatRegistration:
    def test_declares_read_only_annotations(self, fs_stat_tool: Any) -> None:
        assert fs_stat_tool.annotations is not None
        assert fs_stat_tool.annotations.read_only_hint is True
        assert fs_stat_tool.annotations.open_world_hint is False

    def test_publishes_an_output_schema(self, fs_stat_tool: Any) -> None:
        assert fs_stat_tool.output_schema is not None
        assert "type" in fs_stat_tool.output_schema["properties"]


class TestFsStat:
    async def test_stats_a_file(
        self,
        fs_stat: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "f.txt").write_bytes(b"12345")

        result = await fs_stat(root="home", path="f.txt", ctx=mock_ctx)
        output = tool_text(result)

        assert "type: file" in output
        assert "size: 5B" in output
        assert result.structured_content is not None
        assert result.structured_content["root"] == "home"
        assert result.structured_content["type"] == "file"
        assert result.structured_content["size"] == 5

    async def test_stats_a_symlink_without_following(
        self,
        fs_stat: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "link").symlink_to("/etc/passwd")

        output = tool_text(await fs_stat(root="home", path="link", ctx=mock_ctx))

        assert "type: symlink" in output
        assert "target: /etc/passwd" in output

    async def test_missing_path_returns_friendly_error(
        self,
        fs_stat: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        result = await fs_stat(root="home", path="nope.txt", ctx=mock_ctx)
        assert "Error" in tool_text(result)
        assert result.is_error is True

    async def test_path_escape_returns_friendly_error(
        self,
        fs_stat: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        result = await fs_stat(root="home", path="../../etc/passwd", ctx=mock_ctx)
        output = tool_text(result)
        assert "Error" in output
        assert "confined" in output.lower()
        assert result.is_error is True
