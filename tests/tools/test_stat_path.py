"""Tests for fs_stat."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from mcp.server.mcpserver import MCPServer

from af_filesystem_mcp.tools.stat_path import register

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path
    from unittest.mock import MagicMock


@pytest.fixture
def fs_stat() -> Callable[..., Awaitable[str]]:
    mcp = MCPServer("test")
    register(mcp)
    tools = {tool.name: tool.fn for tool in mcp._tool_manager.list_tools()}
    return tools["fs_stat"]


class TestFsStat:
    async def test_stats_a_file(
        self,
        fs_stat: Callable[..., Awaitable[str]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "f.txt").write_bytes(b"12345")

        output = await fs_stat(root="home", path="f.txt", ctx=mock_ctx)

        assert "type: file" in output
        assert "size: 5B" in output

    async def test_stats_a_symlink_without_following(
        self,
        fs_stat: Callable[..., Awaitable[str]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "link").symlink_to("/etc/passwd")

        output = await fs_stat(root="home", path="link", ctx=mock_ctx)

        assert "type: symlink" in output
        assert "target: /etc/passwd" in output

    async def test_missing_path_returns_friendly_error(
        self, fs_stat: Callable[..., Awaitable[str]], mock_ctx: MagicMock
    ) -> None:
        output = await fs_stat(root="home", path="nope.txt", ctx=mock_ctx)
        assert "Error" in output

    async def test_path_escape_returns_friendly_error(
        self, fs_stat: Callable[..., Awaitable[str]], mock_ctx: MagicMock
    ) -> None:
        output = await fs_stat(root="home", path="../../etc/passwd", ctx=mock_ctx)
        assert "Error" in output
        assert "confined" in output.lower()
