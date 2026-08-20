"""Tests for fs_grep."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from mcp.server.mcpserver import MCPServer

from af_filesystem_mcp.tools.grep_files import register

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path
    from unittest.mock import MagicMock


@pytest.fixture
def fs_grep() -> Callable[..., Awaitable[str]]:
    mcp = MCPServer("test")
    register(mcp)
    tools = {tool.name: tool.fn for tool in mcp._tool_manager.list_tools()}
    return tools["fs_grep"]


class TestFsGrep:
    async def test_finds_a_match(
        self,
        fs_grep: Callable[..., Awaitable[str]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "log.txt").write_text(
            "line one\nERROR found\nline three\n"
        )

        output = await fs_grep(root="home", pattern="ERROR", path="", ctx=mock_ctx)

        assert "log.txt:2: ERROR found" in output

    async def test_no_matches_reports_zero(
        self,
        fs_grep: Callable[..., Awaitable[str]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "log.txt").write_text("all clear\n")

        output = await fs_grep(root="home", pattern="ERROR", path="", ctx=mock_ctx)

        assert "0 match" in output

    async def test_does_not_descend_into_symlinked_directories(
        self,
        fs_grep: Callable[..., Awaitable[str]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "bob").mkdir()
        (home_root / "bob" / "secret.txt").write_text("ERROR in bob's file\n")
        (home_root / "alice" / "escape").symlink_to(home_root / "bob")

        output = await fs_grep(root="home", pattern="ERROR", path="", ctx=mock_ctx)

        assert "secret.txt" not in output

    async def test_path_escape_returns_friendly_error(
        self, fs_grep: Callable[..., Awaitable[str]], mock_ctx: MagicMock
    ) -> None:
        output = await fs_grep(root="home", pattern="x", path="../", ctx=mock_ctx)
        assert "Error" in output
