"""Unit tests for af_filesystem_mcp.budgets.

Budgets carries the per-call token/byte ceilings from the CLI (see
test_cli.py) through the lifespan context to call_fs_op's helper-payload
injection (see tests/tools/test_helpers.py) -- here the only contract is
that its defaults match helper.ops's own defaults, so the two cannot drift
apart the way the fs_grep docs and helper.ops.grep_files did (issue #3).
"""

from __future__ import annotations

import pytest

from af_filesystem_mcp.budgets import Budgets
from af_filesystem_mcp.helper import ops


class TestBudgetsDefaults:
    def test_defaults_match_helper_ops_constants(self) -> None:
        budgets = Budgets()
        assert budgets.read_max_bytes == ops.DEFAULT_READ_BYTES_LIMIT
        assert budgets.read_max_file_size == ops.DEFAULT_MAX_READ_FILE_SIZE
        assert budgets.grep_max_output_bytes == ops.DEFAULT_GREP_MAX_OUTPUT_BYTES
        assert budgets.max_line_chars == ops.DEFAULT_MAX_LINE_CHARS

    def test_is_frozen(self) -> None:
        budgets = Budgets()
        with pytest.raises(AttributeError):
            budgets.read_max_bytes = 1  # type: ignore[misc]

    def test_accepts_explicit_overrides(self) -> None:
        budgets = Budgets(
            read_max_bytes=1024,
            read_max_file_size=2048,
            grep_max_output_bytes=512,
            max_line_chars=40,
        )
        assert budgets.read_max_bytes == 1024
        assert budgets.read_max_file_size == 2048
        assert budgets.grep_max_output_bytes == 512
        assert budgets.max_line_chars == 40
