"""Tests for fs_list."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from mcp.server.mcpserver import MCPServer

from af_filesystem_mcp.tools.list_dir import register

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path
    from unittest.mock import MagicMock


@pytest.fixture
def fs_list() -> Callable[..., Awaitable[str]]:
    mcp = MCPServer("test")
    register(mcp)
    tools = {tool.name: tool.fn for tool in mcp._tool_manager.list_tools()}
    return tools["fs_list"]


class TestFsList:
    async def test_lists_home_entries(
        self,
        fs_list: Callable[..., Awaitable[str]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
    ) -> None:
        home_root, _data_root = fs_roots
        (home_root / "alice" / "notes.txt").write_text("hi")

        output = await fs_list(root="home", path="", ctx=mock_ctx)

        assert "notes.txt" in output
        assert "Next actions" in output

    async def test_lists_data_entries_independently(
        self,
        fs_list: Callable[..., Awaitable[str]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
    ) -> None:
        _home_root, data_root = fs_roots
        (data_root / "alice" / "results.csv").write_text("a,b\n")

        output = await fs_list(root="data", path="", ctx=mock_ctx)

        assert "results.csv" in output

    async def test_empty_directory_says_empty(
        self, fs_list: Callable[..., Awaitable[str]], mock_ctx: MagicMock
    ) -> None:
        output = await fs_list(root="home", path="", ctx=mock_ctx)
        assert "(empty)" in output

    async def test_symlink_shows_target_not_followed(
        self,
        fs_list: Callable[..., Awaitable[str]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "escape").symlink_to("/etc/passwd")

        output = await fs_list(root="home", path="", ctx=mock_ctx)

        assert "[symlink] escape -> /etc/passwd" in output

    async def test_path_escape_returns_friendly_error_not_raise(
        self, fs_list: Callable[..., Awaitable[str]], mock_ctx: MagicMock
    ) -> None:
        output = await fs_list(root="home", path="../", ctx=mock_ctx)
        assert "Error" in output
        assert "confined" in output.lower()

    async def test_missing_directory_returns_friendly_error(
        self, fs_list: Callable[..., Awaitable[str]], mock_ctx: MagicMock
    ) -> None:
        output = await fs_list(root="home", path="nope", ctx=mock_ctx)
        assert "Error" in output
        assert "no such" in output.lower()

    async def test_cannot_see_another_users_home(
        self,
        fs_list: Callable[..., Awaitable[str]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "bob").mkdir()
        (home_root / "bob" / "private.txt").write_text("shh")

        # alice (mock_ctx's identity) trying to reach bob's home via `..`.
        output = await fs_list(root="home", path="../bob", ctx=mock_ctx)

        assert "Error" in output
        assert "private.txt" not in output
