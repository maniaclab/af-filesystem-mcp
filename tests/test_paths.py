"""Unit tests for path confinement (af_filesystem_mcp.paths).

These tests need no privilege and no real multi-user setup: they exercise
the *pinning* layer only (policy hygiene / early rejection / prompt-injection
containment). The actual security boundary — POSIX permissions enforced
against the impersonated requesting uid/gid — is exercised separately by
tests/helper/test_ops.py (O_NOFOLLOW opens) and
tests/test_impersonate.py (subprocess identity switch), and cannot be
proven end-to-end without real multiple users, which is why this module's
docstring is explicit that pinning is defense-in-depth, not the boundary
itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from af_filesystem_mcp.paths import PathEscapeError, UserRoots, resolve_confined


class TestResolveConfinedHappyPath:
    def test_root_itself_resolves(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        assert resolve_confined(root, "") == root.resolve()

    def test_plain_relative_file_resolves_under_root(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        (root / "notes.txt").write_text("hi")
        resolved = resolve_confined(root, "notes.txt")
        assert resolved == (root / "notes.txt").resolve()

    def test_nested_relative_path_resolves(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        (root / "a" / "b").mkdir(parents=True)
        (root / "a" / "b" / "c.txt").write_text("hi")
        resolved = resolve_confined(root, "a/b/c.txt")
        assert resolved == (root / "a" / "b" / "c.txt").resolve()

    def test_nonexistent_file_under_root_resolves(self, tmp_path: Path) -> None:
        # fs_read/fs_stat on a missing path should fail with "not found",
        # not with a path-escape error — resolve_confined only pins, it
        # never requires existence (strict=False).
        root = tmp_path / "alice"
        root.mkdir()
        resolved = resolve_confined(root, "does-not-exist.txt")
        assert resolved == (root / "does-not-exist.txt").resolve()

    def test_internal_symlink_within_root_resolves(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        (root / "real.txt").write_text("hi")
        (root / "link.txt").symlink_to(root / "real.txt")
        resolved = resolve_confined(root, "link.txt")
        assert resolved == (root / "real.txt").resolve()


class TestResolveConfinedRejectsEscapes:
    def test_rejects_dotdot_traversal(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        (tmp_path / "bob").mkdir()
        (tmp_path / "bob" / "secret.txt").write_text("shh")
        with pytest.raises(PathEscapeError):
            resolve_confined(root, "../bob/secret.txt")

    def test_rejects_dotdot_chain_back_to_root(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        with pytest.raises(PathEscapeError):
            resolve_confined(root, "a/../../bob/secret.txt")

    def test_rejects_absolute_path_input(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        with pytest.raises(PathEscapeError):
            resolve_confined(root, "/etc/passwd")

    def test_rejects_symlink_escaping_to_sibling_user(self, tmp_path: Path) -> None:
        root = tmp_path / "alice"
        root.mkdir()
        other = tmp_path / "bob"
        other.mkdir()
        (other / "secret.txt").write_text("shh")
        (root / "escape").symlink_to(other / "secret.txt")
        with pytest.raises(PathEscapeError):
            resolve_confined(root, "escape")

    def test_rejects_symlink_escaping_to_world_readable_file(
        self, tmp_path: Path
    ) -> None:
        # Policy confines to the two roots even when the target is
        # POSIX-world-readable (e.g. /etc/passwd): confinement is a stated
        # capability boundary, not merely a mirror of DAC permissions.
        root = tmp_path / "alice"
        root.mkdir()
        (root / "passwd").symlink_to("/etc/passwd")
        with pytest.raises(PathEscapeError):
            resolve_confined(root, "passwd")

    def test_rejects_dangling_symlink_pointing_outside_root(
        self, tmp_path: Path
    ) -> None:
        # The rust-mcp-filesystem vulnerability class (maniaclab/af-mcp-platform#188):
        # validate-then-open on a dangling symlink whose canonicalization
        # falls back to canonical(parent)/filename, silently passing a
        # prefix check. resolve_confined must reject the dangling target
        # itself, not the (in-root) symlink's own parent directory.
        root = tmp_path / "alice"
        root.mkdir()
        (root / "dangling").symlink_to(tmp_path / "bob" / "does-not-exist-yet.txt")
        with pytest.raises(PathEscapeError):
            resolve_confined(root, "dangling")

    def test_rejects_nested_symlink_directory_escape(self, tmp_path: Path) -> None:
        # A symlinked *directory* component, not just a leaf file.
        root = tmp_path / "alice"
        root.mkdir()
        other = tmp_path / "bob"
        (other / "private").mkdir(parents=True)
        (other / "private" / "data.txt").write_text("shh")
        (root / "link-dir").symlink_to(other / "private")
        with pytest.raises(PathEscapeError):
            resolve_confined(root, "link-dir/data.txt")

    def test_rejects_symlink_swap_toctou_style_still_pinned_after_swap(
        self, tmp_path: Path
    ) -> None:
        # Not a full TOCTOU proof (that requires the impersonation boundary,
        # see module docstring) -- just confirms a swapped-in escaping
        # symlink is still caught by a fresh resolve_confined call, i.e.
        # pinning is not cached/stale across calls.
        root = tmp_path / "alice"
        root.mkdir()
        (root / "real.txt").write_text("hi")
        link = root / "link.txt"
        link.symlink_to(root / "real.txt")
        assert resolve_confined(root, "link.txt") == (root / "real.txt").resolve()

        link.unlink()
        link.symlink_to("/etc/passwd")
        with pytest.raises(PathEscapeError):
            resolve_confined(root, "link.txt")


class TestResolveConfinedRootItselfIsSymlink:
    def test_root_may_itself_be_a_symlink_and_still_confines(
        self, tmp_path: Path
    ) -> None:
        # Some deployments mount /home/<user> via a symlink farm; the root
        # being a symlink must not defeat confinement for paths under it.
        real_root = tmp_path / "real-alice"
        real_root.mkdir()
        (real_root / "notes.txt").write_text("hi")
        linked_root = tmp_path / "alice"
        linked_root.symlink_to(real_root)

        resolved = resolve_confined(linked_root, "notes.txt")
        assert resolved == (real_root / "notes.txt").resolve()

    def test_still_rejects_escape_when_root_is_a_symlink(
        self, tmp_path: Path
    ) -> None:
        real_root = tmp_path / "real-alice"
        real_root.mkdir()
        linked_root = tmp_path / "alice"
        linked_root.symlink_to(real_root)

        with pytest.raises(PathEscapeError):
            resolve_confined(linked_root, "../bob/secret.txt")


class TestUserRoots:
    def test_for_unixname_builds_home_and_data_paths(self) -> None:
        roots = UserRoots.for_unixname(
            "alice", home_root=Path("/home"), data_root=Path("/data")
        )
        assert roots.home == Path("/home/alice")
        assert roots.data == Path("/data/alice")

    def test_rejects_unixname_with_path_separator(self) -> None:
        with pytest.raises(ValueError, match="unixname"):
            UserRoots.for_unixname(
                "../etc", home_root=Path("/home"), data_root=Path("/data")
            )

    def test_rejects_empty_unixname(self) -> None:
        with pytest.raises(ValueError, match="unixname"):
            UserRoots.for_unixname(
                "", home_root=Path("/home"), data_root=Path("/data")
            )


def test_resolve_confined_never_raises_on_permission_denied_stat(
    tmp_path: Path,
) -> None:
    # resolve_confined must not need to stat/open anything it resolves --
    # a permission-denied intermediate directory (as would happen crossing
    # into another user's 0700 home under real impersonation) must not
    # turn into an unrelated OSError here; either it resolves (subsequent
    # I/O will then fail under the real uid) or it's rejected as an escape.
    root = tmp_path / "alice"
    root.mkdir()
    locked = tmp_path / "bob"
    locked.mkdir(mode=0o700)
    try:
        with pytest.raises(PathEscapeError):
            resolve_confined(root, "../bob/x.txt")
    finally:
        locked.chmod(0o700)
