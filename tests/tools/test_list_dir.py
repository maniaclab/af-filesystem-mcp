"""Tests for fs_list."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from mcp.server.mcpserver import MCPServer

from af_filesystem_mcp.tools.list_dir import register

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path
    from unittest.mock import MagicMock

    from mcp.types import CallToolResult


@pytest.fixture
def fs_list_tool() -> Any:
    mcp = MCPServer("test")
    register(mcp)
    return next(
        tool for tool in mcp._tool_manager.list_tools() if tool.name == "fs_list"
    )


@pytest.fixture
def fs_list(fs_list_tool: Any) -> Callable[..., Awaitable[CallToolResult]]:
    return fs_list_tool.fn  # type: ignore[no-any-return]


class TestFsListRegistration:
    def test_declares_read_only_annotations(self, fs_list_tool: Any) -> None:
        assert fs_list_tool.annotations is not None
        assert fs_list_tool.annotations.read_only_hint is True
        assert fs_list_tool.annotations.open_world_hint is False

    def test_publishes_an_output_schema(self, fs_list_tool: Any) -> None:
        assert fs_list_tool.output_schema is not None
        assert "entries" in fs_list_tool.output_schema["properties"]


class TestFsList:
    async def test_lists_home_entries(
        self,
        fs_list: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        home_root, _data_root = fs_roots
        (home_root / "alice" / "notes.txt").write_text("hi")

        result = await fs_list(root="home", path="", ctx=mock_ctx)
        output = tool_text(result)

        assert "notes.txt" in output
        assert "Next actions" in output
        assert result.is_error is not True
        assert result.structured_content is not None
        assert result.structured_content["root"] == "home"
        assert result.structured_content["total"] == 1
        assert result.structured_content["entries"][0]["name"] == "notes.txt"

    async def test_lists_data_entries_independently(
        self,
        fs_list: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        _home_root, data_root = fs_roots
        (data_root / "alice" / "results.csv").write_text("a,b\n")

        output = tool_text(await fs_list(root="data", path="", ctx=mock_ctx))

        assert "results.csv" in output

    async def test_empty_directory_says_empty(
        self,
        fs_list: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        output = tool_text(await fs_list(root="home", path="", ctx=mock_ctx))
        assert "(empty)" in output

    async def test_symlink_shows_target_not_followed(
        self,
        fs_list: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "escape").symlink_to("/etc/passwd")

        output = tool_text(await fs_list(root="home", path="", ctx=mock_ctx))

        assert "[symlink] escape -> /etc/passwd" in output

    async def test_path_escape_returns_friendly_error_not_raise(
        self,
        fs_list: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        result = await fs_list(root="home", path="../", ctx=mock_ctx)
        output = tool_text(result)
        assert "Error" in output
        assert "confined" in output.lower()
        assert result.is_error is True

    async def test_missing_directory_returns_friendly_error(
        self,
        fs_list: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        result = await fs_list(root="home", path="nope", ctx=mock_ctx)
        output = tool_text(result)
        assert "Error" in output
        assert "no such" in output.lower()
        assert result.is_error is True

    async def test_cannot_see_another_users_home(
        self,
        fs_list: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "bob").mkdir()
        (home_root / "bob" / "private.txt").write_text("shh")

        # alice (mock_ctx's identity) trying to reach bob's home via `..`.
        result = await fs_list(root="home", path="../bob", ctx=mock_ctx)
        output = tool_text(result)

        assert "Error" in output
        assert "private.txt" not in output
        assert result.is_error is True
