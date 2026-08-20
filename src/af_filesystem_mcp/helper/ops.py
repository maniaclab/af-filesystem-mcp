"""Filesystem operations for the impersonated helper.

Two different symlink policies are in effect, on purpose:

- ``list_dir``/``stat_path`` report metadata *about* directory entries —
  name, type, size, mtime, and (for a symlink) its literal target string —
  using ``lstat`` semantics throughout. They never dereference a symlink to
  read what it points at, so listing/stating a symlink (even one that
  escapes the confined root) is harmless: it discloses nothing but the
  target *string* the user's own directory entry already names.
- ``read_file`` and ``grep_files`` touch file *contents*. Content is where
  rust-mcp-filesystem's actual vulnerability lived (maniaclab/af-mcp-platform#188:
  a dangling-symlink write escape), so both refuse to follow **any**
  symlink at all — not just escaping ones — via
  ``af_filesystem_mcp.paths.secure_open_confined`` (a single fixed target,
  for ``read_file``) or an equivalent O_NOFOLLOW, dir-fd-anchored walk (for
  ``grep_files``, which discovers its own targets as it walks rather than
  resolving one caller-supplied string). This is a deliberately
  conservative v1 restriction: a symlink *within* a user's own confined
  root that points at another file in that same root is still refused, not
  just an escaping one. Loosening that would require proving, at open
  time, that a followed target stays in-root without reintroducing a
  resolve-then-open gap — not worth the complexity until real usage shows
  it is needed.
"""

from __future__ import annotations

import errno
import os
import stat as stat_module
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from collections.abc import Iterator

from af_filesystem_mcp.paths import (
    PathEscapeError,
    resolve_confined,
    secure_open_confined,
)

#: Directory listing page size, absent an explicit ``limit``.
DEFAULT_LIST_LIMIT = 1000
#: No caller-supplied ``limit`` may exceed this, regardless of request.
MAX_LIST_LIMIT = 5000

#: fs_read default/maximum bytes returned per call.
DEFAULT_READ_BYTES_LIMIT = 1_048_576  # 1 MiB
MAX_READ_BYTES_LIMIT = 8 * 1_048_576  # 8 MiB hard cap regardless of caller request

#: fs_read default line count for head/tail/lines modes.
DEFAULT_NUM_LINES = 200
MAX_NUM_LINES = 5000

#: fs_grep defaults/hard caps.
DEFAULT_GREP_MAX_FILES = 500
DEFAULT_GREP_MAX_MATCHES = 200
DEFAULT_GREP_MAX_MATCHES_PER_FILE = 20
DEFAULT_GREP_MAX_DEPTH = 12


ReadMode = Literal["bytes", "head", "tail", "lines"]


def _entry_type(mode: int) -> str:
    if stat_module.S_ISDIR(mode):
        return "dir"
    if stat_module.S_ISLNK(mode):
        return "symlink"
    if stat_module.S_ISREG(mode):
        return "file"
    return "other"


def _lstat_entry(dir_fd: int, name: str) -> dict[str, Any]:
    """Build the JSON-friendly entry dict for *name* within *dir_fd*, via ``lstat`` (never followed)."""
    st = os.lstat(name, dir_fd=dir_fd)
    entry_type = _entry_type(st.st_mode)
    item: dict[str, Any] = {
        "name": name,
        "type": entry_type,
        "size": st.st_size if entry_type == "file" else None,
        "mtime": st.st_mtime,
        "mode": stat_module.S_IMODE(st.st_mode),
    }
    if entry_type == "symlink":
        try:
            item["target"] = os.readlink(name, dir_fd=dir_fd)
        except OSError:
            item["target"] = None
    return item


def list_dir(
    root: Path,
    relative: str,
    *,
    offset: int = 0,
    limit: int = DEFAULT_LIST_LIMIT,
) -> dict[str, Any]:
    """List the entries of the directory at *relative* under *root*.

    Never follows symlinks to determine entry type/size (see module
    docstring); a symlink entry is reported with its literal ``target``
    string, not the target's own metadata.
    """
    limit = min(max(limit, 1), MAX_LIST_LIMIT)
    resolved = resolve_confined(root, relative)

    if not resolved.exists():
        msg = f"no such directory: {relative!r}"
        raise FileNotFoundError(msg)
    if not resolved.is_dir():
        msg = f"not a directory: {relative!r}"
        raise NotADirectoryError(msg)

    dir_fd = os.open(resolved, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with os.scandir(dir_fd) as it:
            names = [entry.name for entry in it]
        entries = [_lstat_entry(dir_fd, name) for name in names]
    finally:
        os.close(dir_fd)

    entries.sort(key=lambda e: str(e["name"]))
    total = len(entries)
    page = entries[offset : offset + limit]
    return {
        "path": relative,
        "entries": page,
        "offset": offset,
        "limit": limit,
        "total": total,
        "truncated": offset + limit < total,
    }


def stat_path(root: Path, relative: str) -> dict[str, Any]:
    """Return lstat-based metadata for *relative* under *root* (never dereferenced).

    Deliberately does **not** just ``lstat(resolve_confined(root, relative))``:
    ``resolve_confined`` fully resolves symlinks (including the final
    component) to decide whether the target is in-bounds, which would make
    a symlink entry indistinguishable from what it points at. Instead, the
    *parent* directory is confined+resolved (following any symlinks in the
    parent chain, as ``resolve_confined`` always does), and the leaf name
    itself is looked up with ``lstat`` relative to that directory --
    exactly the ``list_dir`` policy, applied to a single named entry.
    """
    if not relative:
        resolved_root = root.resolve(strict=False)
        st = os.lstat(resolved_root)
        return {
            "path": relative,
            "name": "",
            "type": _entry_type(st.st_mode),
            "size": None,
            "mtime": st.st_mtime,
            "mode": stat_module.S_IMODE(st.st_mode),
        }

    rel_path = Path(relative)
    parent_relative = "" if rel_path.parent == Path() else str(rel_path.parent)
    leaf_name = rel_path.name

    resolved_parent = resolve_confined(root, parent_relative)
    if not resolved_parent.is_dir():
        msg = f"no such directory: {parent_relative!r}"
        raise FileNotFoundError(msg)

    try:
        dir_fd = os.open(resolved_parent, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            raise FileNotFoundError(str(exc)) from exc
        raise
    try:
        try:
            entry = _lstat_entry(dir_fd, leaf_name)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                raise FileNotFoundError(str(exc)) from exc
            raise
    finally:
        os.close(dir_fd)

    return entry | {"path": relative}


def read_file(
    root: Path,
    relative: str,
    *,
    # `str`, not `ReadMode`, on purpose: the caller across the JSON boundary
    # (helper/__main__.py) receives an arbitrary string from the parent
    # process and has not necessarily validated it against ReadMode's
    # members yet, so the runtime else-clause a few lines down (raising
    # ValueError on an unrecognized mode) is real, reachable defensive
    # code, not dead code a narrower type would make mypy flag as such.
    mode: str = "bytes",
    offset: int = 0,
    length: int | None = None,
    start_line: int = 0,
    num_lines: int = DEFAULT_NUM_LINES,
    max_bytes: int = DEFAULT_READ_BYTES_LIMIT,
) -> dict[str, Any]:
    """Read *relative* under *root*, never following any symlink (see module docstring).

    ``mode="bytes"``: returns bytes ``[offset, offset+length)``, capped at
    *max_bytes* (itself capped at ``MAX_READ_BYTES_LIMIT``).

    ``mode="head"``/``"tail"``: the first/last *num_lines* lines.

    ``mode="lines"``: *num_lines* lines starting at *start_line* (0-based).

    Content is decoded as UTF-8 with invalid sequences replaced (never
    raises on binary content) and returned as a plain ``str`` -- the MCP
    tool layer is the one that decides how to present it to the LLM.
    """
    max_bytes = min(max(max_bytes, 1), MAX_READ_BYTES_LIMIT)

    try:
        fd = secure_open_confined(root, relative, os.O_RDONLY)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            raise FileNotFoundError(str(exc)) from exc
        if exc.errno == errno.EISDIR:
            raise IsADirectoryError(str(exc)) from exc
        raise

    st = os.fstat(fd)
    if stat_module.S_ISDIR(st.st_mode):
        os.close(fd)
        msg = f"{relative!r} is a directory"
        raise IsADirectoryError(msg)

    # os.fdopen(..., closefd=True) takes ownership of fd from this point:
    # it is closed when the `with` block exits, on every path (normal
    # return or an exception raised while reading).
    with os.fdopen(fd, "rb", closefd=True) as fh:
        if mode == "bytes":
            fh.seek(offset)
            requested = length if length is not None else max_bytes
            requested = min(max(requested, 0), max_bytes)
            raw = fh.read(requested + 1)
            truncated = len(raw) > requested
            content = raw[:requested]
        else:
            num_lines = min(max(num_lines, 1), MAX_NUM_LINES)
            all_lines = fh.read(max_bytes + 1).splitlines(keepends=True)
            truncated = len(b"".join(all_lines)) > max_bytes
            if mode == "head":
                selected = all_lines[:num_lines]
            elif mode == "tail":
                selected = all_lines[-num_lines:]
            elif mode == "lines":
                selected = all_lines[start_line : start_line + num_lines]
            else:  # pragma: no cover - guarded by the tool layer's enum
                msg = f"unknown read mode: {mode!r}"
                raise ValueError(msg)
            content = b"".join(selected)

    return {
        "path": relative,
        "content": content.decode("utf-8", errors="replace"),
        "truncated": truncated,
    }


def _iter_files_no_follow(
    root: Path, relative: str, *, max_depth: int
) -> Iterator[tuple[int, str, str]]:
    """Yield ``(dir_fd, name, relative_path)`` for regular files under *root*/*relative*.

    Walks directories via ``os.open(..., dir_fd=parent_fd, O_NOFOLLOW)`` so
    a symlinked directory anywhere in the subtree is never descended into,
    and every entry's type comes from ``lstat`` (never dereferenced) so a
    symlinked *file* is never yielded either. This is the recursive
    analogue of ``secure_open_confined``'s single-path walk: it discovers
    each subdirectory fd from a scandir it just performed, rather than
    resolving any caller-supplied string beyond the initial *relative*.
    """
    resolve_confined(root, relative)  # early, clear rejection

    start = root / relative if relative else root
    root_fd = os.open(start, os.O_RDONLY | os.O_DIRECTORY)
    stack: list[tuple[int, str, int]] = [(root_fd, "", 0)]
    try:
        while stack:
            dir_fd, prefix, depth = stack.pop()
            try:
                with os.scandir(dir_fd) as it:
                    scanned = sorted(it, key=lambda e: e.name)
                for entry in scanned:
                    rel_name = f"{prefix}/{entry.name}" if prefix else entry.name
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat_module.S_ISLNK(st.st_mode):
                        continue
                    if stat_module.S_ISDIR(st.st_mode):
                        if depth + 1 > max_depth:
                            continue
                        try:
                            sub_fd = os.open(
                                entry.name,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=dir_fd,
                            )
                        except OSError:
                            continue
                        stack.append((sub_fd, rel_name, depth + 1))
                    elif stat_module.S_ISREG(st.st_mode):
                        yield dir_fd, entry.name, rel_name
            finally:
                if dir_fd != root_fd:
                    os.close(dir_fd)
    finally:
        os.close(root_fd)


def grep_files(
    root: Path,
    relative: str,
    *,
    pattern: str,
    max_files: int = DEFAULT_GREP_MAX_FILES,
    max_matches: int = DEFAULT_GREP_MAX_MATCHES,
    max_matches_per_file: int = DEFAULT_GREP_MAX_MATCHES_PER_FILE,
    max_depth: int = DEFAULT_GREP_MAX_DEPTH,
) -> dict[str, Any]:
    """Search for the substring *pattern* in files under *relative* (recursive, capped).

    Never descends into or reads through a symlink (see module docstring).
    Binary files (content that cannot be decoded as UTF-8) are skipped
    without raising. Stops as soon as either *max_files* files have been
    scanned or *max_matches* total matches have been collected --
    ``truncated`` tells the caller which (if either) cap was hit.
    """
    matches: list[dict[str, Any]] = []
    files_scanned = 0
    truncated = False

    for dir_fd, name, rel_path in _iter_files_no_follow(
        root, relative, max_depth=max_depth
    ):
        if files_scanned >= max_files or len(matches) >= max_matches:
            truncated = True
            break
        files_scanned += 1

        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
        except OSError:
            continue

        per_file_matches = 0
        with os.fdopen(fd, "rb") as fh:
            for line_number, raw_line in enumerate(fh, start=1):
                if per_file_matches >= max_matches_per_file or len(matches) >= max_matches:
                    truncated = True
                    break
                try:
                    line = raw_line.decode("utf-8")
                except UnicodeDecodeError:
                    break  # treat as binary; skip the rest of this file
                if pattern in line:
                    matches.append(
                        {
                            "path": rel_path,
                            "line_number": line_number,
                            "line": line.rstrip("\n"),
                        }
                    )
                    per_file_matches += 1

        if len(matches) >= max_matches:
            truncated = True
            break

    return {
        "path": relative,
        "pattern": pattern,
        "matches": matches,
        "files_scanned": files_scanned,
        "truncated": truncated,
    }


__all__ = [
    "PathEscapeError",
    "grep_files",
    "list_dir",
    "read_file",
    "stat_path",
]
