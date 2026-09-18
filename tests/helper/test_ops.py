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

    def test_reports_the_files_real_size(self, root: Path) -> None:
        (root / "f.txt").write_bytes(b"x" * 42)
        result = ops.read_file(root, "f.txt", mode="bytes")
        assert result["size"] == 42

    def test_refuses_a_bare_whole_file_read_of_an_oversized_file(
        self, root: Path
    ) -> None:
        # issue #5: a bare fs_read (no offset/length) of a file bigger than
        # max_file_size must be refused outright, naming the real size,
        # rather than silently returning a truncated window with no
        # indication of how much was left out.
        (root / "big.txt").write_bytes(b"x" * 100)
        with pytest.raises(ValueError, match="100"):
            ops.read_file(root, "big.txt", mode="bytes", max_file_size=50)

    def test_size_guard_does_not_block_an_explicit_offset(self, root: Path) -> None:
        (root / "big.txt").write_bytes(b"x" * 100)
        result = ops.read_file(
            root, "big.txt", mode="bytes", offset=90, max_file_size=50
        )
        assert result["content"] == "x" * 10

    def test_size_guard_does_not_block_an_explicit_length(self, root: Path) -> None:
        (root / "big.txt").write_bytes(b"x" * 100)
        result = ops.read_file(
            root, "big.txt", mode="bytes", length=10, max_file_size=50
        )
        assert result["content"] == "x" * 10

    def test_size_guard_does_not_apply_to_tail_mode(self, root: Path) -> None:
        (root / "big.txt").write_bytes(b"x" * 100)
        result = ops.read_file(root, "big.txt", mode="tail", max_file_size=50)
        assert result["content"] == "x" * 100


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
        result = ops.read_file(root, "f.txt", mode="lines", start_line=2, num_lines=3)
        assert result["content"] == "line2\nline3\nline4\n"

    def test_lines_range_past_end_of_file_returns_available_lines_only(
        self, root: Path
    ) -> None:
        result = ops.read_file(root, "f.txt", mode="lines", start_line=8, num_lines=10)
        assert result["content"] == "line8\nline9\n"

    def test_head_truncates_at_max_bytes(self, root: Path) -> None:
        result = ops.read_file(root, "f.txt", mode="head", num_lines=100, max_bytes=12)
        assert result["content"] == "line0\nline1\n"
        assert result["truncated"] is True


class TestReadFileTailOfLargeFile:
    """issue #4: tail must return the file's real tail, not the tail of the
    first max_bytes window -- these use a file much larger than max_bytes
    so the pre-fix bug (returning an arbitrary middle-of-file slice) would
    fail every assertion here.
    """

    @pytest.fixture
    def big_file(self, root: Path) -> list[str]:
        lines = [f"line{i:04d}\n" for i in range(1000)]
        (root / "big.txt").write_text("".join(lines))
        return lines

    def test_tail_returns_the_files_actual_last_lines(
        self, root: Path, big_file: list[str]
    ) -> None:
        result = ops.read_file(root, "big.txt", mode="tail", num_lines=3, max_bytes=50)
        assert result["content"] == "".join(big_file[-3:])
        assert result["truncated"] is True

    def test_tail_of_a_file_that_fits_within_max_bytes_is_not_truncated(
        self, root: Path, big_file: list[str]
    ) -> None:
        result = ops.read_file(
            root, "big.txt", mode="tail", num_lines=3, max_bytes=len(big_file) * 9
        )
        assert result["content"] == "".join(big_file[-3:])
        assert result["truncated"] is False

    def test_lines_mode_reaches_a_range_past_the_first_max_bytes_window(
        self, root: Path, big_file: list[str]
    ) -> None:
        # Before the fix, `lines` only ever looked inside the first
        # `max_bytes` bytes of the file, so a start_line beyond that
        # window silently returned nothing.
        result = ops.read_file(
            root, "big.txt", mode="lines", start_line=900, num_lines=3, max_bytes=50
        )
        assert result["content"] == "".join(big_file[900:903])


class TestGrepFiles:
    """grep_files groups matches by file (issue #5's RTK-shaped output):

    ``{"files": [{"path", "match_count", "matches": [{"line_number", "line",
    "truncated"}]}], "files_scanned", "total_matches", "truncated"}`` --
    replacing the old flat ``matches`` list, which repeated ``path`` on
    every match instead of once per file.
    """

    def test_finds_matches_in_a_single_file(self, root: Path) -> None:
        (root / "a.txt").write_text("hello\nneedle here\nbye\n")
        result = ops.grep_files(root, "", pattern="needle")
        assert result["files"] == [
            {
                "path": "a.txt",
                "match_count": 1,
                "matches": [
                    {"line_number": 2, "line": "needle here", "truncated": False}
                ],
            }
        ]
        assert result["total_matches"] == 1

    def test_finds_matches_across_multiple_files_recursively(self, root: Path) -> None:
        (root / "sub").mkdir()
        (root / "a.txt").write_text("needle in a\n")
        (root / "sub" / "b.txt").write_text("needle in b\n")

        result = ops.grep_files(root, "", pattern="needle")
        paths = sorted(f["path"] for f in result["files"])
        assert paths == ["a.txt", str(Path("sub") / "b.txt")]
        assert result["total_matches"] == 2

    def test_caps_total_matches(self, root: Path) -> None:
        (root / "a.txt").write_text("\n".join(["needle"] * 50))
        result = ops.grep_files(root, "", pattern="needle", max_matches=5)
        assert result["total_matches"] == 5
        assert result["truncated"] is True

    def test_caps_files_scanned(self, root: Path) -> None:
        for i in range(5):
            (root / f"f{i}.txt").write_text("needle\n")
        result = ops.grep_files(root, "", pattern="needle", max_files=2)
        assert result["files_scanned"] == 2
        assert result["truncated"] is True

    def test_clamps_max_matches_to_the_documented_hard_limit(self, root: Path) -> None:
        # issue #3: the tool docstring promises a hard limit of 200 total
        # matches regardless of what the caller asks for. Spread across
        # files so the (separately clamped) per-file cap doesn't mask this.
        for i in range(20):
            (root / f"f{i}.txt").write_text("\n".join(["needle"] * 50))
        result = ops.grep_files(
            root,
            "",
            pattern="needle",
            max_matches=100_000,
            max_files=100_000,
            max_matches_per_file=100_000,
        )
        assert result["total_matches"] == ops.MAX_GREP_MAX_MATCHES

    def test_clamps_max_files_to_the_documented_hard_limit(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # issue #3: the tool docstring promises a hard limit of 500 files
        # scanned regardless of what the caller asks for. A smaller ceiling
        # is monkeypatched in so the test doesn't need 501 real files.
        monkeypatch.setattr(ops, "MAX_GREP_MAX_FILES", 3)
        for i in range(5):
            (root / f"f{i}.txt").write_text("needle\n")
        result = ops.grep_files(root, "", pattern="needle", max_files=100_000)
        assert result["files_scanned"] == 3

    def test_clamps_max_matches_per_file_to_the_documented_hard_limit(
        self, root: Path
    ) -> None:
        (root / "a.txt").write_text("\n".join(["needle"] * 50))
        result = ops.grep_files(
            root,
            "",
            pattern="needle",
            max_matches_per_file=100_000,
            max_matches=100_000,
        )
        assert result["total_matches"] == ops.MAX_GREP_MAX_MATCHES_PER_FILE

    def test_clamps_max_depth_to_the_documented_hard_limit(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ops, "MAX_GREP_MAX_DEPTH", 1)
        nested = root / "a" / "b"
        nested.mkdir(parents=True)
        (nested / "deep.txt").write_text("needle\n")
        result = ops.grep_files(root, "", pattern="needle", max_depth=100_000)
        assert result["files"] == []

    def test_truncates_long_lines_to_max_line_chars(self, root: Path) -> None:
        # issue #5: a single long line (e.g. minified JS/JSON) must not
        # come back in full -- each snippet is capped independently of the
        # match-count caps.
        long_line = "x" * 500 + "needle" + "y" * 500
        (root / "a.txt").write_text(long_line + "\n")
        result = ops.grep_files(root, "", pattern="needle", max_line_chars=50)
        match = result["files"][0]["matches"][0]
        assert len(match["line"]) == 50
        assert match["line"] == long_line[:50]
        assert match["truncated"] is True

    def test_does_not_truncate_lines_within_max_line_chars(self, root: Path) -> None:
        (root / "a.txt").write_text("short needle line\n")
        result = ops.grep_files(root, "", pattern="needle", max_line_chars=200)
        match = result["files"][0]["matches"][0]
        assert match["line"] == "short needle line"
        assert match["truncated"] is False

    def test_caps_total_output_bytes_across_many_small_matches(
        self, root: Path
    ) -> None:
        # issue #5: max_matches alone still allows max_matches * max_line_chars
        # bytes back; max_output_bytes is the total-snippet-bytes budget on
        # top of that.
        (root / "a.txt").write_text("\n".join(["needle " + "z" * 90] * 200))
        result = ops.grep_files(
            root,
            "",
            pattern="needle",
            max_matches=200,
            max_line_chars=100,
            max_output_bytes=500,
        )
        total_snippet_bytes = sum(
            len(m["line"].encode("utf-8"))
            for f in result["files"]
            for m in f["matches"]
        )
        # The budget is checked before each match is added, not mid-line, so
        # the total can overshoot by up to one match's worth (max_line_chars)
        # before the next check trips it.
        assert total_snippet_bytes <= 500 + 100
        assert result["total_matches"] < 200
        assert result["truncated"] is True

    def test_does_not_descend_into_symlinked_directories(self, root: Path) -> None:
        other = root.parent / "bob"
        (other).mkdir()
        (other / "secret.txt").write_text("needle in bob\n")
        (root / "escape-dir").symlink_to(other)

        result = ops.grep_files(root, "", pattern="needle")
        assert result["files"] == []

    def test_does_not_read_symlinked_files(self, root: Path) -> None:
        (root / "target.txt").write_text("needle\n")
        (root / "link.txt").symlink_to(root / "target.txt")

        # "target.txt" itself is a real file grep should find; "link.txt"
        # must be skipped rather than read through.
        result = ops.grep_files(root, "", pattern="needle")
        assert [f["path"] for f in result["files"]] == ["target.txt"]

    def test_raises_path_escape_for_traversal(self, root: Path) -> None:
        with pytest.raises(PathEscapeError):
            ops.grep_files(root, "../", pattern="needle")
