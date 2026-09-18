"""Tests for fs_read."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from mcp.server.mcpserver import MCPServer

from af_filesystem_mcp.tools.read_file import register

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path
    from unittest.mock import MagicMock

    from mcp.types import CallToolResult


@pytest.fixture
def fs_read_tool() -> Any:
    mcp = MCPServer("test")
    register(mcp)
    return next(
        tool for tool in mcp._tool_manager.list_tools() if tool.name == "fs_read"
    )


@pytest.fixture
def fs_read(fs_read_tool: Any) -> Callable[..., Awaitable[CallToolResult]]:
    return fs_read_tool.fn  # type: ignore[no-any-return]


class TestFsReadRegistration:
    def test_declares_read_only_annotations(self, fs_read_tool: Any) -> None:
        assert fs_read_tool.annotations is not None
        assert fs_read_tool.annotations.read_only_hint is True
        assert fs_read_tool.annotations.open_world_hint is False

    def test_publishes_an_output_schema(self, fs_read_tool: Any) -> None:
        assert fs_read_tool.output_schema is not None
        assert "content" in fs_read_tool.output_schema["properties"]


class TestFsRead:
    async def test_reads_whole_file_by_default(
        self,
        fs_read: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "f.txt").write_text("hello world")

        result = await fs_read(root="home", path="f.txt", ctx=mock_ctx)
        output = tool_text(result)

        assert output.startswith("hello world")
        assert result.structured_content is not None
        assert result.structured_content["root"] == "home"
        assert result.structured_content["content"] == "hello world"
        assert result.structured_content["truncated"] is False
        assert result.structured_content["size"] == len("hello world")

    async def test_head_mode_returns_first_lines(
        self,
        fs_read: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "f.txt").write_text(
            "\n".join(f"L{i}" for i in range(10))
        )

        output = tool_text(
            await fs_read(
                root="home", path="f.txt", mode="head", num_lines=2, ctx=mock_ctx
            )
        )

        assert output.startswith("L0\nL1")
        assert "L9" not in output

    async def test_oversized_bare_read_returns_a_friendly_error(
        self,
        fs_read: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        # issue #5: a bare fs_read (no offset/length) of a file larger than
        # the server's whole-file-read limit (default 8 MiB) must be
        # refused with a clear error rather than silently truncated.
        home_root, _ = fs_roots
        big = home_root / "alice" / "big.bin"
        big.write_bytes(b"x" * (8 * 1024 * 1024 + 1))

        result = await fs_read(root="home", path="big.bin", ctx=mock_ctx)
        output = tool_text(result)

        assert result.is_error is True
        assert "Error" in output

    async def test_refuses_to_follow_symlink(
        self,
        fs_read: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "target.txt").write_text("secret")
        (home_root / "alice" / "link.txt").symlink_to(
            home_root / "alice" / "target.txt"
        )

        result = await fs_read(root="home", path="link.txt", ctx=mock_ctx)
        output = tool_text(result)

        assert "Error" in output
        assert "secret" not in output
        assert result.is_error is True

    async def test_missing_file_returns_friendly_error(
        self,
        fs_read: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        result = await fs_read(root="home", path="nope.txt", ctx=mock_ctx)
        assert "Error" in tool_text(result)
        assert result.is_error is True

    async def test_directory_returns_friendly_error(
        self,
        fs_read: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "sub").mkdir()

        result = await fs_read(root="home", path="sub", ctx=mock_ctx)
        output = tool_text(result)

        assert "Error" in output
        assert "directory" in output.lower()
        assert result.is_error is True

    async def test_cannot_read_another_users_file(
        self,
        fs_read: Callable[..., Awaitable[CallToolResult]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
        tool_text: Callable[[CallToolResult], str],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "bob").mkdir()
        (home_root / "bob" / "private.txt").write_text("bob's secret")

        result = await fs_read(root="home", path="../bob/private.txt", ctx=mock_ctx)
        output = tool_text(result)

        assert "Error" in output
        assert "secret" not in output
        assert result.is_error is True
