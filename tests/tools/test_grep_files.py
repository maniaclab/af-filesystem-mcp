"""Tests for fs_grep."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from mcp.server.mcpserver import MCPServer

from af_filesystem_mcp.tools.grep_files import register

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path
    from unittest.mock import MagicMock

    from mcp.types import CallToolResult


@pytest.fixture
def fs_grep_tool() -> Any:
    mcp = MCPServer("test")
    register(mcp)
    return next(
        tool for tool in mcp._tool_manager.list_tools() if tool.name == "fs_grep"
    )


@pytest.fixture
def fs_grep(fs_grep_tool: Any) -> Callable[..., Awaitable[CallToolResult]]:
    return fs_grep_tool.fn  # type: ignore[no-any-return]


class TestFsGrepRegistration:
    def test_declares_read_only_annotations(self, fs_grep_tool: Any) -> None:
        assert fs_grep_tool.annotations is not None
        assert fs_grep_tool.annotations.read_only_hint is True
        assert fs_grep_tool.annotations.open_world_hint is False

    def test_publishes_an_output_schema(self, fs_grep_tool: Any) -> None:
        assert fs_grep_tool.output_schema is not None
        assert "files" in fs_grep_tool.output_schema["properties"]


class TestFsGrep:
    async def test_finds_a_match(
        self,
        fs_grep: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "log.txt").write_text(
            "line one\nERROR found\nline three\n"
        )

        result = await fs_grep(root="home", pattern="ERROR", path="", ctx=mock_ctx)
        output = tool_text(result)

        assert "log.txt (1 matches)" in output
        assert "2: ERROR found" in output
        assert result.structured_content is not None
        assert result.structured_content["root"] == "home"
        assert result.structured_content["pattern"] == "ERROR"
        assert result.structured_content["files"] == [
            {
                "path": "log.txt",
                "match_count": 1,
                "matches": [
                    {"line_number": 2, "line": "ERROR found", "truncated": False}
                ],
            }
        ]

    async def test_no_matches_reports_zero(
        self,
        fs_grep: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "log.txt").write_text("all clear\n")

        output = tool_text(
            await fs_grep(root="home", pattern="ERROR", path="", ctx=mock_ctx)
        )

        assert "0 match" in output

    async def test_does_not_descend_into_symlinked_directories(
        self,
        fs_grep: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "bob").mkdir()
        (home_root / "bob" / "secret.txt").write_text("ERROR in bob's file\n")
        (home_root / "alice" / "escape").symlink_to(home_root / "bob")

        output = tool_text(
            await fs_grep(root="home", pattern="ERROR", path="", ctx=mock_ctx)
        )

        assert "secret.txt" not in output

    async def test_path_escape_returns_friendly_error(
        self,
        fs_grep: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        result = await fs_grep(root="home", pattern="x", path="../", ctx=mock_ctx)
        assert "Error" in tool_text(result)
        assert result.is_error is True
