"""Tests for the `python -m af_filesystem_mcp.helper <op> <json>` CLI.

This is the process ``af_filesystem_mcp.impersonate.run_helper`` launches
per call (impersonating the caller in production); here it is exercised as
a plain function call (``main(argv)``) with ``pytest.raises(SystemExit)`` and
``capsys``, matching how the rest of this suite avoids needing real
privilege to test the helper's own logic.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from af_filesystem_mcp.helper.__main__ import main

if TYPE_CHECKING:
    from pathlib import Path


def _payload(**kwargs: object) -> str:
    return json.dumps(kwargs)


class TestSuccessfulOps:
    def test_list_op_prints_json_result(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        (root / "f.txt").write_text("hi")

        main(["list", _payload(root=str(root), relative="")])

        out = json.loads(capsys.readouterr().out)
        assert out["entries"][0]["name"] == "f.txt"

    def test_stat_op_prints_json_result(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        (root / "f.txt").write_text("hi")

        main(["stat", _payload(root=str(root), relative="f.txt")])

        out = json.loads(capsys.readouterr().out)
        assert out["type"] == "file"

    def test_read_op_prints_json_result(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        (root / "f.txt").write_text("hello")

        main(["read", _payload(root=str(root), relative="f.txt", mode="bytes")])

        out = json.loads(capsys.readouterr().out)
        assert out["content"] == "hello"

    def test_grep_op_prints_json_result(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        (root / "f.txt").write_text("needle\n")

        main(["grep", _payload(root=str(root), relative="", pattern="needle")])

        out = json.loads(capsys.readouterr().out)
        assert out["matches"][0]["path"] == "f.txt"


class TestErrorHandling:
    def test_unknown_op_exits_nonzero_with_tagged_stderr(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["bogus", _payload(root="/tmp", relative="")])
        assert exc_info.value.code != 0
        assert "unknown operation" in capsys.readouterr().err

    def test_malformed_json_exits_nonzero(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit):
            main(["list", "not json"])
        assert "ERROR:" in capsys.readouterr().err

    def test_path_escape_is_tagged(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        with pytest.raises(SystemExit):
            main(["list", _payload(root=str(root), relative="../")])
        assert capsys.readouterr().err.startswith("PATH_ESCAPE:")

    def test_not_found_is_tagged(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        with pytest.raises(SystemExit):
            main(["stat", _payload(root=str(root), relative="nope.txt")])
        assert capsys.readouterr().err.startswith("NOT_FOUND:")

    def test_missing_root_key_is_an_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit):
            main(["list", _payload(relative="")])
        assert "root" in capsys.readouterr().err

    def test_wrong_argc_is_an_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit):
            main(["list"])
        assert "usage" in capsys.readouterr().err
