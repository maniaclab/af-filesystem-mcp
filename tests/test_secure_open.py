"""Tests for secure_open_confined: the open-time, TOCTOU-closing layer.

resolve_confined (tests/test_paths.py) is a string-level check performed
once before I/O; between that check and an eventual plain open() call, a
symlink could in principle be swapped in. secure_open_confined closes that
window by walking root -> target one path component at a time using
os.open(..., dir_fd=..., O_NOFOLLOW) -- an openat-style walk where *every*
component, intermediate or final, fails outright (ELOOP) if it turns out to
be a symlink, rather than silently being followed. That is what directly
defeats the rust-mcp-filesystem vulnerability class this design was chosen
to avoid (maniaclab/af-mcp-platform#188): a dangling-symlink write escape
via a validate-then-open gap.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from af_filesystem_mcp.paths import PathEscapeError, secure_open_confined

if TYPE_CHECKING:
    from pathlib import Path


def _read_all(fd: int) -> bytes:
    with os.fdopen(fd, "rb") as fh:
        return fh.read()


class TestSecureOpenHappyPath:
    def test_opens_plain_file_under_root(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        (root / "notes.txt").write_bytes(b"hello")

        fd = secure_open_confined(root, "notes.txt", os.O_RDONLY)
        assert _read_all(fd) == b"hello"

    def test_opens_nested_file_under_root(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        (root / "a" / "b").mkdir(parents=True)
        (root / "a" / "b" / "c.txt").write_bytes(b"nested")

        fd = secure_open_confined(root, "a/b/c.txt", os.O_RDONLY)
        assert _read_all(fd) == b"nested"


class TestSecureOpenRejectsFinalSymlink:
    def test_refuses_to_follow_symlink_leaf_pointing_outside_root(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        (tmp_path / "bob").mkdir()
        (tmp_path / "bob" / "secret.txt").write_bytes(b"shh")
        (root / "escape").symlink_to(tmp_path / "bob" / "secret.txt")

        with pytest.raises(PathEscapeError):
            secure_open_confined(root, "escape", os.O_RDONLY)

    def test_refuses_to_follow_symlink_leaf_even_when_pinning_missed_it(
        self, tmp_path: Path
    ) -> None:
        # Simulates the TOCTOU scenario: pretend resolve_confined already
        # ran and approved a path that, by the time secure_open_confined
        # actually opens it, has been swapped to an escaping symlink.
        # secure_open_confined must still refuse -- it does not trust that
        # an earlier check is still valid, because the open-time O_NOFOLLOW
        # is unconditional regardless of what any prior check concluded.
        root = tmp_path / "alice"
        root.mkdir()
        target = root / "swapped.txt"
        target.write_bytes(b"originally a real file")
        target.unlink()
        target.symlink_to("/etc/passwd")

        with pytest.raises(PathEscapeError):
            secure_open_confined(root, "swapped.txt", os.O_RDONLY)

    def test_refuses_dangling_symlink_leaf(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        (root / "dangling").symlink_to(tmp_path / "bob" / "nonexistent.txt")

        with pytest.raises(PathEscapeError):
            secure_open_confined(root, "dangling", os.O_RDONLY)


class TestSecureOpenRejectsIntermediateSymlink:
    def test_refuses_symlinked_intermediate_directory(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        other = tmp_path / "bob"
        (other / "private").mkdir(parents=True)
        (other / "private" / "data.txt").write_bytes(b"shh")
        (root / "link-dir").symlink_to(other / "private")

        with pytest.raises(PathEscapeError):
            secure_open_confined(root, "link-dir/data.txt", os.O_RDONLY)


class TestSecureOpenRejectsTraversal:
    def test_rejects_dotdot_traversal(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        (tmp_path / "bob").mkdir()
        (tmp_path / "bob" / "secret.txt").write_bytes(b"shh")

        with pytest.raises(PathEscapeError):
            secure_open_confined(root, "../bob/secret.txt", os.O_RDONLY)

    def test_rejects_absolute_path(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        root.mkdir()

        with pytest.raises(PathEscapeError):
            secure_open_confined(root, "/etc/passwd", os.O_RDONLY)

    def test_rejects_empty_relative_path(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        root.mkdir()

        with pytest.raises(ValueError, match="relative"):
            secure_open_confined(root, "", os.O_RDONLY)


class TestSecureOpenMissingFile:
    def test_missing_file_raises_file_not_found(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        root.mkdir()

        with pytest.raises(FileNotFoundError):
            secure_open_confined(root, "nope.txt", os.O_RDONLY)

    def test_missing_intermediate_directory_raises_file_not_found(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "alice"
        root.mkdir()

        with pytest.raises(FileNotFoundError):
            secure_open_confined(root, "no/such/dir/file.txt", os.O_RDONLY)
