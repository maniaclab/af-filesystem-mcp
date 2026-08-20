"""Unit tests for af_filesystem_mcp.helper.ops.

These call the op functions directly (no subprocess, no privilege) --
exactly what the impersonated helper subprocess calls once it is already
running as the target uid/gid. Path-confinement string-level tests already
live in tests/test_paths.py and tests/test_secure_open.py; here the focus
is each operation's own contract: pagination, ranges/caps, and the
content-read ops' stricter "never follow any symlink" policy (see
ops.py's module docstring for why list/stat and read/grep apply different
symlink policies).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from af_filesystem_mcp.helper import ops
from af_filesystem_mcp.paths import PathEscapeError


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "alice"
    r.mkdir()
    return r


class TestListDir:
    def test_lists_files_and_dirs_sorted_by_name(self, root: Path) -> None:
        (root / "b.txt").write_text("b")
        (root / "a.txt").write_text("a")
        (root / "sub").mkdir()

        result = ops.list_dir(root, "")

        names = [e["name"] for e in result["entries"]]
        assert names == ["a.txt", "b.txt", "sub"]
        types = {e["name"]: e["type"] for e in result["entries"]}
        assert types == {"a.txt": "file", "b.txt": "file", "sub": "dir"}

    def test_reports_file_size_and_none_for_dirs(self, root: Path) -> None:
        (root / "f.txt").write_bytes(b"12345")
        (root / "sub").mkdir()

        result = ops.list_dir(root, "")
        by_name = {e["name"]: e for e in result["entries"]}
        assert by_name["f.txt"]["size"] == 5
        assert by_name["sub"]["size"] is None

    def test_reports_symlinks_without_following_and_includes_target(
        self, root: Path
    ) -> None:
        (root / "real.txt").write_text("hi")
        (root / "link.txt").symlink_to(root / "real.txt")
        (root / "escaping-link").symlink_to("/etc/passwd")

        result = ops.list_dir(root, "")
        by_name = {e["name"]: e for e in result["entries"]}
        assert by_name["link.txt"]["type"] == "symlink"
        assert by_name["link.txt"]["target"] == str(root / "real.txt")
        # Escaping symlinks are still just *listed* (as a name+type+target
        # triple, never followed) -- listing metadata about a directory's
        # own entries is not a content read, so pinning does not apply here.
        assert by_name["escaping-link"]["type"] == "symlink"
        assert by_name["escaping-link"]["target"] == "/etc/passwd"

    def test_paginates_with_offset_and_limit(self, root: Path) -> None:
        for i in range(10):
            (root / f"f{i:02d}.txt").write_text("x")

        page = ops.list_dir(root, "", offset=2, limit=3)
        assert [e["name"] for e in page["entries"]] == ["f02.txt", "f03.txt", "f04.txt"]
        assert page["total"] == 10
        assert page["truncated"] is True

        last_page = ops.list_dir(root, "", offset=9, limit=3)
        assert [e["name"] for e in last_page["entries"]] == ["f09.txt"]
        assert last_page["truncated"] is False

    def test_lists_nested_subdirectory(self, root: Path) -> None:
        (root / "sub" / "inner").mkdir(parents=True)
        (root / "sub" / "file.txt").write_text("x")

        result = ops.list_dir(root, "sub")
        names = {e["name"] for e in result["entries"]}
        assert names == {"inner", "file.txt"}

    def test_raises_file_not_found_for_missing_directory(self, root: Path) -> None:
        with pytest.raises(FileNotFoundError):
            ops.list_dir(root, "nope")

    def test_raises_not_a_directory_for_a_file(self, root: Path) -> None:
        (root / "f.txt").write_text("x")
        with pytest.raises(NotADirectoryError):
            ops.list_dir(root, "f.txt")

    def test_raises_path_escape_for_traversal(self, root: Path) -> None:
        with pytest.raises(PathEscapeError):
            ops.list_dir(root, "../")


class TestStatPath:
    def test_stats_a_file(self, root: Path) -> None:
        (root / "f.txt").write_bytes(b"12345")
        result = ops.stat_path(root, "f.txt")
        assert result["type"] == "file"
        assert result["size"] == 5
        assert "mtime" in result
        assert "mode" in result

    def test_stats_a_directory(self, root: Path) -> None:
        (root / "sub").mkdir()
        result = ops.stat_path(root, "sub")
        assert result["type"] == "dir"

    def test_stats_a_symlink_without_following(self, root: Path) -> None:
        (root / "target.txt").write_text("hi")
        (root / "link.txt").symlink_to(root / "target.txt")
        result = ops.stat_path(root, "link.txt")
        assert result["type"] == "symlink"
        assert result["target"] == str(root / "target.txt")

    def test_stats_root_itself(self, root: Path) -> None:
        result = ops.stat_path(root, "")
        assert result["type"] == "dir"

    def test_raises_file_not_found(self, root: Path) -> None:
        with pytest.raises(FileNotFoundError):
            ops.stat_path(root, "nope.txt")

    def test_raises_path_escape_for_traversal(self, root: Path) -> None:
        with pytest.raises(PathEscapeError):
            ops.stat_path(root, "../etc/passwd")


class TestReadFileBytesMode:
    def test_reads_whole_small_file(self, root: Path) -> None:
        (root / "f.txt").write_bytes(b"hello world")
        result = ops.read_file(root, "f.txt", mode="bytes")
        assert result["content"] == "hello world"
        assert result["truncated"] is False

    def test_reads_byte_range(self, root: Path) -> None:
        (root / "f.txt").write_bytes(b"0123456789")
        result = ops.read_file(root, "f.txt", mode="bytes", offset=2, length=3)
        assert result["content"] == "234"

    def test_caps_length_at_max_read_bytes(self, root: Path) -> None:
        (root / "f.txt").write_bytes(b"x" * 100)
        result = ops.read_file(root, "f.txt", mode="bytes", length=10, max_bytes=5)
        assert len(result["content"]) == 5
        assert result["truncated"] is True

    def test_refuses_to_follow_symlink(self, root: Path) -> None:
        (root / "target.txt").write_text("secret")
        (root / "link.txt").symlink_to(root / "target.txt")
        with pytest.raises(PathEscapeError):
            ops.read_file(root, "link.txt", mode="bytes")

    def test_raises_is_a_directory(self, root: Path) -> None:
        (root / "sub").mkdir()
        with pytest.raises(IsADirectoryError):
            ops.read_file(root, "sub", mode="bytes")

    def test_raises_file_not_found(self, root: Path) -> None:
        with pytest.raises(FileNotFoundError):
            ops.read_file(root, "nope.txt", mode="bytes")


class TestReadFileLineModes:
    @pytest.fixture(autouse=True)
    def _write_ten_lines(self, root: Path) -> None:
        lines = [f"line{i}\n" for i in range(10)]
        (root / "f.txt").write_text("".join(lines))

    def test_head_returns_first_n_lines(self, root: Path) -> None:
        result = ops.read_file(root, "f.txt", mode="head", num_lines=3)
        assert result["content"] == "line0\nline1\nline2\n"

    def test_tail_returns_last_n_lines(self, root: Path) -> None:
        result = ops.read_file(root, "f.txt", mode="tail", num_lines=3)
        assert result["content"] == "line7\nline8\nline9\n"

    def test_lines_returns_requested_range(self, root: Path) -> None:
        result = ops.read_file(
            root, "f.txt", mode="lines", start_line=2, num_lines=3
        )
        assert result["content"] == "line2\nline3\nline4\n"

    def test_lines_range_past_end_of_file_returns_available_lines_only(
        self, root: Path
    ) -> None:
        result = ops.read_file(
            root, "f.txt", mode="lines", start_line=8, num_lines=10
        )
        assert result["content"] == "line8\nline9\n"


class TestGrepFiles:
    def test_finds_matches_in_a_single_file(self, root: Path) -> None:
        (root / "a.txt").write_text("hello\nneedle here\nbye\n")
        result = ops.grep_files(root, "", pattern="needle")
        assert result["matches"] == [
            {"path": "a.txt", "line_number": 2, "line": "needle here"}
        ]

    def test_finds_matches_across_multiple_files_recursively(self, root: Path) -> None:
        (root / "sub").mkdir()
        (root / "a.txt").write_text("needle in a\n")
        (root / "sub" / "b.txt").write_text("needle in b\n")

        result = ops.grep_files(root, "", pattern="needle")
        paths = sorted(m["path"] for m in result["matches"])
        assert paths == ["a.txt", str(Path("sub") / "b.txt")]

    def test_caps_total_matches(self, root: Path) -> None:
        (root / "a.txt").write_text("\n".join(["needle"] * 50))
        result = ops.grep_files(root, "", pattern="needle", max_matches=5)
        assert len(result["matches"]) == 5
        assert result["truncated"] is True

    def test_caps_files_scanned(self, root: Path) -> None:
        for i in range(5):
            (root / f"f{i}.txt").write_text("needle\n")
        result = ops.grep_files(root, "", pattern="needle", max_files=2)
        assert result["files_scanned"] == 2
        assert result["truncated"] is True

    def test_does_not_descend_into_symlinked_directories(self, root: Path) -> None:
        other = root.parent / "bob"
        (other).mkdir()
        (other / "secret.txt").write_text("needle in bob\n")
        (root / "escape-dir").symlink_to(other)

        result = ops.grep_files(root, "", pattern="needle")
        assert result["matches"] == []

    def test_does_not_read_symlinked_files(self, root: Path) -> None:
        (root / "target.txt").write_text("needle\n")
        (root / "link.txt").symlink_to(root / "target.txt")

        # "target.txt" itself is a real file grep should find; "link.txt"
        # must be skipped rather than read through.
        result = ops.grep_files(root, "", pattern="needle")
        assert [m["path"] for m in result["matches"]] == ["target.txt"]

    def test_raises_path_escape_for_traversal(self, root: Path) -> None:
        with pytest.raises(PathEscapeError):
            ops.grep_files(root, "../", pattern="needle")
