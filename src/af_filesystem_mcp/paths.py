"""Path confinement: pin a user-supplied relative path to a per-user root.

This is policy hygiene and prompt-injection containment, **not** the
security boundary. The real boundary is that every actual filesystem
operation runs in a subprocess impersonating the requesting user's real
uid/gid (see ``af_filesystem_mcp.impersonate``): the kernel — and, for the
NFS-mounted homes, the NFS server — enforces every permission check against
that real identity, so a symlink that somehow slipped past this pinning
could only ever reach what the impersonated uid could already reach. Pinning
exists on top of that so the tool surface itself stays confined to a user's
own two roots (``/home/<unixname>`` and ``/data/<unixname>``) even when the
target of an escape would otherwise be world-readable (e.g. ``/etc/passwd``)
— see maniaclab/af-mcp-platform#188's rejection of rust-mcp-filesystem for
exactly the class of bug (dangling-symlink write escape via a
validate-then-open TOCTOU) this module is written to avoid within its own
layer.

``resolve_confined`` fully resolves symlinks (via ``Path.resolve(strict=False)``)
before pinning, including dangling ones (whose *unresolved literal target*,
read straight from the symlink, is what gets checked) — it never falls back
to checking only the symlink's own (in-root) parent directory the way
rust-mcp-filesystem's ``validate_path`` did.
"""

from __future__ import annotations

import errno
import os
from dataclasses import dataclass
from pathlib import Path


class PathEscapeError(Exception):
    """Raised when a requested path resolves outside its confined root."""


def resolve_confined(root: Path, relative: str) -> Path:
    """Resolve *relative* against *root* and confine it to that root.

    *relative* must be a relative path (no leading ``/``); an absolute path
    is always rejected regardless of where it points, matching the tool
    contract that every fs_* call takes a path relative to one of the
    caller's two roots. *root* itself may be a symlink (e.g. a symlink-farm
    homes layout) — only the path *within* it is confined.

    Existence is never required: a path that resolves to a location that
    does not (yet) exist under *root* is returned as-is (``strict=False``)
    so callers can distinguish "escapes the root" (raised here) from "does
    not exist" (raised by the actual I/O that follows, as a normal
    not-found error).

    Raises:
        PathEscapeError: if *relative* is absolute, or the fully resolved
            path (following every symlink component, including a dangling
            symlink's literal recorded target) is not under *root*.
    """
    if relative:
        rel_path = Path(relative)
        if rel_path.is_absolute():
            msg = f"absolute paths are not allowed: {relative!r}"
            raise PathEscapeError(msg)
        candidate = root / rel_path
    else:
        candidate = root

    resolved_root = root.resolve(strict=False)
    resolved = candidate.resolve(strict=False)

    try:
        common = os.path.commonpath([str(resolved), str(resolved_root)])
    except ValueError:
        # Raised by commonpath for mismatched path styles (e.g. different
        # drives on Windows) -- never a legitimate "under root" case.
        msg = f"{relative!r} escapes the confined root {root}"
        raise PathEscapeError(msg) from None

    if common != str(resolved_root):
        msg = f"{relative!r} escapes the confined root {root}"
        raise PathEscapeError(msg)

    return resolved


def secure_open_confined(root: Path, relative: str, flags: int, *, mode: int = 0o600) -> int:
    """Open *relative* under *root*, refusing to follow any symlink anywhere along the path.

    ``resolve_confined`` (above) is a string-level check performed once,
    before any I/O; a symlink could in principle be swapped in between that
    check and a later plain ``open()``. This function closes that window: it
    walks *root* -> target one path component at a time via
    ``os.open(part, ..., dir_fd=parent_fd)`` with ``O_NOFOLLOW`` forced on
    *every* component (intermediate directories and the final component
    alike). If any component turns out to be a symlink at the moment it is
    actually opened, that open fails outright (``ELOOP``) — there is no
    "resolve now, trust it later" gap for an attacker to race, because
    nothing is ever resolved ahead of the open that uses it. This is the
    direct fix for the exact bug class rust-mcp-filesystem shipped
    (dangling-symlink write escape via a validate-then-open TOCTOU,
    maniaclab/af-mcp-platform#188).

    Still runs ``resolve_confined`` first purely for a clearer, single
    ``PathEscapeError`` message on paths that are obviously out of bounds
    (absolute, ``..``) before spending any syscalls on the component walk.

    Returns the open file descriptor (caller owns it — close it, e.g. via
    ``os.fdopen(fd, ...)`` as a context manager).

    Raises:
        ValueError: if *relative* is empty (there is nothing to open; use
            ``resolve_confined`` if you specifically need the root path).
        PathEscapeError: if the string-level check rejects *relative*, or
            any path component turns out to be a symlink.
        FileNotFoundError, NotADirectoryError: normal lookup failures,
            propagated as-is.
    """
    if not relative:
        msg = "relative path must be non-empty"
        raise ValueError(msg)

    resolve_confined(root, relative)  # cheap, clear-message early rejection

    parts = Path(relative).parts
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    current_fd = root_fd
    try:
        for index, part in enumerate(parts):
            is_last = index == len(parts) - 1
            component_flags = os.O_NOFOLLOW | (
                flags if is_last else (os.O_RDONLY | os.O_DIRECTORY)
            )
            try:
                next_fd = os.open(part, component_flags, mode, dir_fd=current_fd)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    msg = (
                        f"{relative!r} contains a symlink component "
                        f"({part!r}); refusing to follow it"
                    )
                    raise PathEscapeError(msg) from exc
                raise
            if current_fd != root_fd:
                os.close(current_fd)
            current_fd = next_fd
    except BaseException:
        # current_fd is either still root_fd (the very first component's
        # open() failed) or a since-superseded intermediate fd -- either
        # way it is the only fd besides root_fd that could still be open at
        # this point, and each is closed exactly once here.
        if current_fd != root_fd:
            os.close(current_fd)
        os.close(root_fd)
        raise
    else:
        # The loop ran at least once (relative is non-empty, checked above),
        # so current_fd now holds the final component's own fd, distinct
        # from root_fd, which is no longer needed as a dir_fd anchor.
        os.close(root_fd)
        return current_fd


@dataclass(frozen=True)
class UserRoots:
    """The two confinement roots a filesystem tool call is pinned to for one user."""

    home: Path
    data: Path

    @classmethod
    def for_unixname(cls, unixname: str, *, home_root: Path, data_root: Path) -> UserRoots:
        """Build the per-user roots ``{home_root}/{unixname}`` and ``{data_root}/{unixname}``.

        Rejects a *unixname* containing a path separator or ``..`` component,
        or an empty string — the POSIX claim in a broker-issued token is
        trusted identity, but this guards against a malformed or malicious
        claim value being used to construct a path outside the intended
        per-user subtree of ``home_root``/``data_root``.
        """
        if not unixname or "/" in unixname or unixname in {".", ".."}:
            msg = f"invalid unixname claim: {unixname!r}"
            raise ValueError(msg)
        return cls(home=home_root / unixname, data=data_root / unixname)
