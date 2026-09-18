"""Tests for the CLI argument parsing."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from af_filesystem_mcp.budgets import Budgets
from af_filesystem_mcp.cli import main


class TestCliServe:
    def test_serve_defaults_to_stdio(self) -> None:
        captured: dict[str, Any] = {}

        def fake_serve(**kwargs: Any) -> None:
            captured["kwargs"] = kwargs

        with (
            patch("sys.argv", ["af-filesystem-mcp", "serve"]),
            patch("af_filesystem_mcp.cli.serve", fake_serve),
        ):
            main()

        assert captured["kwargs"]["transport"] == "stdio"
        assert captured["kwargs"]["home_root"] == "/home"
        assert captured["kwargs"]["data_root"] == "/data"

    def test_broker_flags_are_forwarded(self) -> None:
        captured: dict[str, Any] = {}

        def fake_serve(**kwargs: Any) -> None:
            captured["kwargs"] = kwargs

        argv = [
            "af-filesystem-mcp",
            "serve",
            "--transport",
            "http",
            "--host",
            "0.0.0.0",
            "--port",
            "8123",
            "--broker-url",
            "https://broker.example.com",
            "--broker-audience",
            "af-filesystem-mcp",
            "--resource-url",
            "https://af-fs.example.org",
        ]
        with (
            patch("sys.argv", argv),
            patch("af_filesystem_mcp.cli.serve", fake_serve),
        ):
            main()

        kwargs = captured["kwargs"]
        assert kwargs["transport"] == "http"
        assert kwargs["host"] == "0.0.0.0"
        assert kwargs["port"] == 8123
        assert kwargs["broker_url"] == "https://broker.example.com"
        assert kwargs["broker_audience"] == "af-filesystem-mcp"
        assert kwargs["resource_url"] == "https://af-fs.example.org"

    def test_default_broker_audience_is_own_name(self) -> None:
        captured: dict[str, Any] = {}

        def fake_serve(**kwargs: Any) -> None:
            captured["kwargs"] = kwargs

        with (
            patch("sys.argv", ["af-filesystem-mcp", "serve"]),
            patch("af_filesystem_mcp.cli.serve", fake_serve),
            patch.dict("os.environ", {}, clear=True),
        ):
            main()

        assert captured["kwargs"]["broker_audience"] == "af-filesystem-mcp"

    def test_home_and_data_root_flags_are_forwarded(self) -> None:
        captured: dict[str, Any] = {}

        def fake_serve(**kwargs: Any) -> None:
            captured["kwargs"] = kwargs

        argv = [
            "af-filesystem-mcp",
            "serve",
            "--home-root",
            "/custom/home",
            "--data-root",
            "/custom/data",
        ]
        with (
            patch("sys.argv", argv),
            patch("af_filesystem_mcp.cli.serve", fake_serve),
        ):
            main()

        assert captured["kwargs"]["home_root"] == "/custom/home"
        assert captured["kwargs"]["data_root"] == "/custom/data"

    def test_budget_flags_are_forwarded(self) -> None:
        captured: dict[str, Any] = {}

        def fake_serve(**kwargs: Any) -> None:
            captured["kwargs"] = kwargs

        argv = [
            "af-filesystem-mcp",
            "serve",
            "--max-read-bytes",
            "1024",
            "--max-read-file-size",
            "2048",
            "--max-grep-output-bytes",
            "4096",
            "--max-line-chars",
            "50",
        ]
        with (
            patch("sys.argv", argv),
            patch("af_filesystem_mcp.cli.serve", fake_serve),
        ):
            main()

        kwargs = captured["kwargs"]
        assert kwargs["max_read_bytes"] == 1024
        assert kwargs["max_read_file_size"] == 2048
        assert kwargs["max_grep_output_bytes"] == 4096
        assert kwargs["max_line_chars"] == 50

    def test_budget_flags_default_to_budgets_defaults(self) -> None:
        captured: dict[str, Any] = {}

        def fake_serve(**kwargs: Any) -> None:
            captured["kwargs"] = kwargs

        with (
            patch("sys.argv", ["af-filesystem-mcp", "serve"]),
            patch("af_filesystem_mcp.cli.serve", fake_serve),
            patch.dict("os.environ", {}, clear=True),
        ):
            main()

        kwargs = captured["kwargs"]
        assert kwargs["max_read_bytes"] == Budgets().read_max_bytes
        assert kwargs["max_read_file_size"] == Budgets().read_max_file_size
        assert kwargs["max_grep_output_bytes"] == Budgets().grep_max_output_bytes
        assert kwargs["max_line_chars"] == Budgets().max_line_chars

    def test_no_command_prints_help(self, capsys) -> None:
        with patch("sys.argv", ["af-filesystem-mcp"]):
            main()
        assert "usage" in capsys.readouterr().out.lower()
