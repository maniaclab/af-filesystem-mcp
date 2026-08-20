"""Tests for af_filesystem_mcp.tools._helpers: the per-call orchestration glue.

call_fs_op resolves identity + per-user roots from the MCP lifespan
context, then runs the impersonated helper subprocess for real (not
mocked) -- in this test environment the process is not root, so
af_filesystem_mcp.impersonate skips the user=/group= kwargs and the
helper simply runs as the test's own uid, exactly like local/stdio mode.
This exercises the full call_fs_op -> run_helper_json -> `python -m
af_filesystem_mcp.helper` -> ops.py chain end-to-end against a real
temp-directory root, without mocking any of it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest

from af_filesystem_mcp.auth.broker import IdentityError
from af_filesystem_mcp.identity import Identity
from af_filesystem_mcp.impersonate import HelperError, HelperTimeoutError
from af_filesystem_mcp.roots import RootsConfig
from af_filesystem_mcp.tools._helpers import (
    append_next_actions,
    call_fs_op,
    format_error,
    resolve_context,
)

if TYPE_CHECKING:
    from pathlib import Path


def _make_ctx(*, home_root: Path, data_root: Path, unixname: str = "alice") -> MagicMock:
    ctx = MagicMock()

    async def _identity_resolver(_ctx: Any) -> Identity:
        return Identity(uid=1234, gid=5678, unixname=unixname)

    ctx.request_context.lifespan_context = {
        "identity_resolver": _identity_resolver,
        "roots_config": RootsConfig(home_root=home_root, data_root=data_root),
    }
    return ctx


class TestResolveContext:
    async def test_builds_roots_from_identity_unixname(self, tmp_path: Path) -> None:
        home_root = tmp_path / "home"
        data_root = tmp_path / "data"
        ctx = _make_ctx(home_root=home_root, data_root=data_root, unixname="alice")

        identity, roots = await resolve_context(ctx)

        assert identity.unixname == "alice"
        assert roots.home == home_root / "alice"
        assert roots.data == data_root / "alice"


class TestCallFsOp:
    async def test_list_runs_the_real_impersonated_helper(self, tmp_path: Path) -> None:
        home_root = tmp_path / "home"
        (home_root / "alice").mkdir(parents=True)
        (home_root / "alice" / "f.txt").write_text("hi")
        ctx = _make_ctx(home_root=home_root, data_root=tmp_path / "data")

        result = await call_fs_op(ctx, "list", "home", "")

        assert result["entries"][0]["name"] == "f.txt"

    async def test_data_root_is_selected_independently_of_home(
        self, tmp_path: Path
    ) -> None:
        home_root = tmp_path / "home"
        data_root = tmp_path / "data"
        (home_root / "alice").mkdir(parents=True)
        (data_root / "alice").mkdir(parents=True)
        (data_root / "alice" / "d.txt").write_text("hi")
        ctx = _make_ctx(home_root=home_root, data_root=data_root)

        result = await call_fs_op(ctx, "list", "data", "")

        assert result["entries"][0]["name"] == "d.txt"

    async def test_invalid_root_name_raises_value_error(self, tmp_path: Path) -> None:
        ctx = _make_ctx(home_root=tmp_path / "home", data_root=tmp_path / "data")
        with pytest.raises(ValueError, match="root"):
            await call_fs_op(ctx, "list", "nope", "")  # type: ignore[arg-type]

    async def test_path_escape_surfaces_as_helper_error(self, tmp_path: Path) -> None:
        home_root = tmp_path / "home"
        (home_root / "alice").mkdir(parents=True)
        ctx = _make_ctx(home_root=home_root, data_root=tmp_path / "data")

        with pytest.raises(HelperError, match="PATH_ESCAPE"):
            await call_fs_op(ctx, "list", "home", "../")

    async def test_per_user_concurrency_semaphore_is_reused_across_calls(
        self, tmp_path: Path
    ) -> None:
        home_root = tmp_path / "home"
        (home_root / "alice").mkdir(parents=True)
        ctx = _make_ctx(home_root=home_root, data_root=tmp_path / "data")

        await call_fs_op(ctx, "list", "home", "")
        await call_fs_op(ctx, "list", "home", "")

        semaphores = ctx.request_context.lifespan_context["_semaphores"]
        assert list(semaphores) == ["alice"]


class TestFormatError:
    def test_helper_error_path_escape_gets_a_friendly_prefix(self) -> None:
        message = format_error(HelperError("PATH_ESCAPE: 'x' escapes root"))
        assert "confined" in message.lower()

    def test_helper_error_not_found_gets_a_friendly_prefix(self) -> None:
        message = format_error(HelperError("NOT_FOUND: no such file"))
        assert "no such" in message.lower()

    def test_helper_error_unknown_tag_falls_back_to_raw_message(self) -> None:
        message = format_error(HelperError("SOMETHING_WEIRD: detail"))
        assert "SOMETHING_WEIRD" in message

    def test_helper_timeout_error_is_recognizable(self) -> None:
        message = format_error(HelperTimeoutError("timed out after 10.0s"))
        assert "time" in message.lower()

    def test_identity_error_message_passthrough(self) -> None:
        message = format_error(IdentityError("no POSIX claims"))
        assert "no POSIX claims" in message

    def test_hints_are_appended(self) -> None:
        message = format_error(ValueError("bad"), hints=["Try again."])
        assert "Try again." in message


def test_append_next_actions_appends_bulleted_list() -> None:
    result = append_next_actions("output", ["Do X.", "Do Y."])
    assert "output" in result
    assert "- Do X." in result
    assert "- Do Y." in result


def test_append_next_actions_no_hints_returns_output_unchanged() -> None:
    assert append_next_actions("output", []) == "output"
