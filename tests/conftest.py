"""Shared fixtures: a mock MCP Context wired to real (tmp_path-based) confinement roots.

Tool-level tests exercise the full call_fs_op -> run_helper_json -> `python
-m af_filesystem_mcp.helper` -> ops.py chain for real (see
tests/tools/test_helpers.py's module docstring for why: in this
environment the process is not root, so no mocking is needed to keep it
safe -- af_filesystem_mcp.impersonate simply skips impersonation, exactly
like local/stdio mode).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest
from mcp.types import TextContent

from af_filesystem_mcp.identity import Identity
from af_filesystem_mcp.roots import RootsConfig

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from mcp.types import CallToolResult


@pytest.fixture
def tool_text() -> Callable[[CallToolResult], str]:
    """Return a helper that extracts a tool's CallToolResult's markdown text block.

    Every fs_* tool returns exactly one TextContent block alongside its
    (optional) structured_content -- this is the substring-assertion
    equivalent of the plain-string return the tools used to have.
    """

    def _tool_text(result: CallToolResult) -> str:
        block = result.content[0]
        assert isinstance(block, TextContent)
        return block.text

    return _tool_text


@pytest.fixture
def fs_roots(tmp_path: Path) -> tuple[Path, Path]:
    """Create and return (home_root, data_root), each with an `alice` subdirectory."""
    home_root = tmp_path / "home"
    data_root = tmp_path / "data"
    (home_root / "alice").mkdir(parents=True)
    (data_root / "alice").mkdir(parents=True)
    return home_root, data_root


@pytest.fixture
def mock_ctx(fs_roots: tuple[Path, Path]) -> MagicMock:
    """A mock MCP Context resolving to unixname "alice" with real per-user roots."""
    home_root, data_root = fs_roots
    ctx: MagicMock = MagicMock()

    async def _identity_resolver(_ctx: Any) -> Identity:
        return Identity(uid=1234, gid=5678, unixname="alice")

    ctx.request_context.lifespan_context = {
        "identity_resolver": _identity_resolver,
        "roots_config": RootsConfig(home_root=home_root, data_root=data_root),
    }
    return ctx


def pytest_addoption(parser: Any) -> None:
    """Add command line options for test categories."""
    parser.addoption(
        "--runslow", action="store_true", default=False, help="run slow tests"
    )


def pytest_collection_modifyitems(config: Any, items: Any) -> None:
    """Skip tests based on command line options."""
    if not config.getoption("--runslow"):
        skip_slow = pytest.mark.skip(reason="need --runslow option to run")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)
