"""Tests for fs_read."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from mcp.server.mcpserver import MCPServer

from af_filesystem_mcp.tools.read_file import register

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path
    from unittest.mock import MagicMock


@pytest.fixture
def fs_read() -> Callable[..., Awaitable[str]]:
    mcp = MCPServer("test")
    register(mcp)
    tools = {tool.name: tool.fn for tool in mcp._tool_manager.list_tools()}
    return tools["fs_read"]


class TestFsRead:
    async def test_reads_whole_file_by_default(
        self,
        fs_read: Callable[..., Awaitable[str]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "f.txt").write_text("hello world")

        output = await fs_read(root="home", path="f.txt", ctx=mock_ctx)

        assert output.startswith("hello world")

    async def test_head_mode_returns_first_lines(
        self,
        fs_read: Callable[..., Awaitable[str]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "f.txt").write_text(
            "\n".join(f"L{i}" for i in range(10))
        )

        output = await fs_read(
            root="home", path="f.txt", mode="head", num_lines=2, ctx=mock_ctx
        )

        assert output.startswith("L0\nL1")
        assert "L9" not in output

    async def test_refuses_to_follow_symlink(
        self,
        fs_read: Callable[..., Awaitable[str]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "target.txt").write_text("secret")
        (home_root / "alice" / "link.txt").symlink_to(
            home_root / "alice" / "target.txt"
        )

        output = await fs_read(root="home", path="link.txt", ctx=mock_ctx)

        assert "Error" in output
        assert "secret" not in output

    async def test_missing_file_returns_friendly_error(
        self, fs_read: Callable[..., Awaitable[str]], mock_ctx: MagicMock
    ) -> None:
        output = await fs_read(root="home", path="nope.txt", ctx=mock_ctx)
        assert "Error" in output

    async def test_directory_returns_friendly_error(
        self,
        fs_read: Callable[..., Awaitable[str]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "alice" / "sub").mkdir()

        output = await fs_read(root="home", path="sub", ctx=mock_ctx)

        assert "Error" in output
        assert "directory" in output.lower()

    async def test_cannot_read_another_users_file(
        self,
        fs_read: Callable[..., Awaitable[str]],
        mock_ctx: MagicMock,
        fs_roots: tuple[Path, Path],
    ) -> None:
        home_root, _ = fs_roots
        (home_root / "bob").mkdir()
        (home_root / "bob" / "private.txt").write_text("bob's secret")

        output = await fs_read(root="home", path="../bob/private.txt", ctx=mock_ctx)

        assert "Error" in output
        assert "secret" not in output
