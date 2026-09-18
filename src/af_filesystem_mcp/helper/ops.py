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
from typing import IO, TYPE_CHECKING, Any, Literal, NamedTuple

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

#: fs_read default/maximum bytes returned per call. 64 KiB (~16k tokens) is
#: sized to fit nearly any single source file/config in one call without
#: risking a multi-hundred-thousand-token result the way the old 1 MiB
#: default (~260k tokens) could (issue #5).
DEFAULT_READ_BYTES_LIMIT = 64 * 1024  # 64 KiB
MAX_READ_BYTES_LIMIT = 256 * 1024  # 256 KiB hard cap regardless of caller request

#: A bare whole-file `mode="bytes"` read (no offset/length given) on a file
#: larger than this is refused outright rather than silently truncated --
#: see read_file's docstring for exactly which requests this guard applies
#: to. offset/length/head/tail/lines reads are never blocked by this; only
#: an unbounded "just read me everything" request on an oversized file is.
DEFAULT_MAX_READ_FILE_SIZE = 8 * 1_048_576  # 8 MiB

#: fs_read default line count for head/tail/lines modes.
DEFAULT_NUM_LINES = 200
MAX_NUM_LINES = 5000

#: fs_grep defaults (also the pre-#3 values, which were never enforced).
DEFAULT_GREP_MAX_FILES = 500
DEFAULT_GREP_MAX_MATCHES = 200
DEFAULT_GREP_MAX_MATCHES_PER_FILE = 20
DEFAULT_GREP_MAX_DEPTH = 12

#: fs_grep hard ceilings -- issue #3: the tool docstring already promised
#: these numbers as hard limits, but nothing clamped a caller-supplied value
#: to them. Kept separate from the DEFAULT_GREP_* names above so "default"
#: and "ceiling" can never silently mean the same number again.
MAX_GREP_MAX_FILES = 500
MAX_GREP_MAX_MATCHES = 200
MAX_GREP_MAX_MATCHES_PER_FILE = 20
MAX_GREP_MAX_DEPTH = 12

#: Each returned match's line text is truncated to this many characters
#: (issue #5): a single-line minified/JSON file could otherwise make one
#: "match" megabytes long.
DEFAULT_MAX_LINE_CHARS = 200

#: Total budget, in bytes of (already-truncated) snippet text, for one
#: fs_grep call -- on top of max_matches, since max_matches alone still
#: allows up to max_matches * max_line_chars bytes back.
DEFAULT_GREP_MAX_OUTPUT_BYTES = 64 * 1024  # 64 KiB


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


def _read_head(fh: IO[bytes], *, num_lines: int, max_bytes: int) -> tuple[bytes, bool]:
    """Return ``(content, truncated)`` for ``mode="head"``: the first *num_lines* lines, capped at *max_bytes*."""
    raw = fh.read(max_bytes + 1)
    truncated = len(raw) > max_bytes
    raw = raw[:max_bytes]
    lines = raw.splitlines(keepends=True)
    if truncated and lines and not lines[-1].endswith(b"\n"):
        # The byte cap landed mid-line; drop the partial trailing
        # fragment rather than return a line cut off mid-content.
        lines = lines[:-1]
    return b"".join(lines[:num_lines]), truncated


def _read_tail(
    fh: IO[bytes], *, size: int, num_lines: int, max_bytes: int
) -> tuple[bytes, bool]:
    """Return ``(content, truncated)`` for ``mode="tail"``: the file's real last *num_lines* lines.

    Issue #4: seeks to the last *max_bytes* bytes of the file rather than
    reading from the start, so tailing a file larger than *max_bytes*
    returns the file's actual tail, not lines from an arbitrary earlier
    window (the previous bug: the first *max_bytes* were read, then the
    last *num_lines* of *that* window were taken).
    """
    seek_pos = max(0, size - max_bytes)
    fh.seek(seek_pos)
    raw = fh.read()
    lines = raw.splitlines(keepends=True)
    if seek_pos > 0 and lines:
        # Landed mid-line (true unless seek_pos happens to fall exactly on
        # a line boundary) -- drop the partial leading fragment so a
        # truncated first line is never mistaken for a real one.
        lines = lines[1:]
    return b"".join(lines[-num_lines:]), seek_pos > 0


def _read_lines(
    fh: IO[bytes], *, start_line: int, num_lines: int, max_bytes: int
) -> tuple[bytes, bool]:
    """Return ``(content, truncated)`` for ``mode="lines"``: *num_lines* lines starting at *start_line*.

    Streams from the start of the file rather than slicing a fixed front
    window, so a *start_line* beyond the first *max_bytes* bytes is still
    reachable (issue #4) -- the cost of reaching it is a forward scan of
    the skipped lines, bounded by the helper subprocess's overall
    wall-clock timeout rather than by *max_bytes*.
    """
    selected: list[bytes] = []
    total_bytes = 0
    truncated = False
    for index, line in enumerate(fh):
        if index < start_line:
            continue
        if len(selected) >= num_lines:
            break
        total_bytes += len(line)
        if total_bytes > max_bytes:
            truncated = True
            break
        selected.append(line)
    return b"".join(selected), truncated


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
    max_file_size: int = DEFAULT_MAX_READ_FILE_SIZE,
) -> dict[str, Any]:
    """Read *relative* under *root*, never following any symlink (see module docstring).

    ``mode="bytes"``: returns bytes ``[offset, offset+length)``, capped at
    *max_bytes* (itself capped at ``MAX_READ_BYTES_LIMIT``). A *bare* whole-
    file request (no *offset*, no *length*) on a file larger than
    *max_file_size* is refused outright with a ``ValueError`` naming the
    real size, rather than silently returning a truncated window with no
    indication of how much was left out (issue #5) -- an explicit *offset*
    or *length* is never blocked by this, since it is already a bounded
    request.

    ``mode="head"``/``"tail"``: the first/last *num_lines* lines. ``tail``
    seeks to the file's real last *max_bytes* bytes rather than reading
    from the start (issue #4) -- tailing a file larger than *max_bytes*
    returns the file's actual tail, not lines from an arbitrary earlier
    window.

    ``mode="lines"``: *num_lines* lines starting at *start_line* (0-based),
    reachable anywhere in the file (not just the first *max_bytes*).

    Content is decoded as UTF-8 with invalid sequences replaced (never
    raises on binary content) and returned as a plain ``str`` -- the MCP
    tool layer is the one that decides how to present it to the LLM. The
    file's real ``size`` is always reported alongside ``content``, so a
    caller can tell a small truncation (one page of a big file) apart from
    "this is the entire file".
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

    if (
        mode == "bytes"
        and offset == 0
        and length is None
        and st.st_size > max_file_size
    ):
        os.close(fd)
        msg = (
            f"{relative!r} is {st.st_size} bytes, larger than the "
            f"{max_file_size}-byte limit for a bare whole-file read -- use "
            "mode='head'/'tail'/'lines', or mode='bytes' with an explicit "
            "offset/length, to read part of it"
        )
        raise ValueError(msg)

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
            if mode == "head":
                content, truncated = _read_head(
                    fh, num_lines=num_lines, max_bytes=max_bytes
                )
            elif mode == "tail":
                content, truncated = _read_tail(
                    fh, size=st.st_size, num_lines=num_lines, max_bytes=max_bytes
                )
            elif mode == "lines":
                content, truncated = _read_lines(
                    fh, start_line=start_line, num_lines=num_lines, max_bytes=max_bytes
                )
            else:  # pragma: no cover - guarded by the tool layer's enum
                msg = f"unknown read mode: {mode!r}"
                raise ValueError(msg)

    return {
        "path": relative,
        "content": content.decode("utf-8", errors="replace"),
        "truncated": truncated,
        "size": st.st_size,
    }


class _EntryOutcome(NamedTuple):
    """What one scandir entry turned out to be, for `_iter_files_no_follow`'s walk."""

    is_file: bool
    sub_fd: int | None  # set only when is_file is False (a directory to descend into)


def _classify_scanned_entry(
    entry: os.DirEntry[str], dir_fd: int, *, depth: int, max_depth: int
) -> _EntryOutcome | None:
    """Classify one scandir *entry* as a file, a directory to descend into, or None to skip.

    Skipped for any of: an ``lstat`` failure, a symlink (never followed --
    see the module docstring), a directory beyond *max_depth*, or a
    directory that fails to open (permission denied, or it vanished/changed
    between the scandir and the open). None of these are errors worth
    raising -- a single bad entry just doesn't appear in the walk.
    """
    try:
        st = entry.stat(follow_symlinks=False)
    except OSError:
        return None
    if stat_module.S_ISLNK(st.st_mode):
        return None
    if stat_module.S_ISDIR(st.st_mode):
        if depth + 1 > max_depth:
            return None
        sub_fd = _open_subdir_no_follow(entry.name, dir_fd)
        if sub_fd is None:
            return None
        return _EntryOutcome(is_file=False, sub_fd=sub_fd)
    if stat_module.S_ISREG(st.st_mode):
        return _EntryOutcome(is_file=True, sub_fd=None)
    return None


def _open_subdir_no_follow(entry_name: str, dir_fd: int) -> int | None:
    """Open *entry_name* as a subdirectory fd under *dir_fd*, or None if it can't be opened."""
    try:
        return os.open(
            entry_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=dir_fd,
        )
    except OSError:
        return None


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
                    outcome = _classify_scanned_entry(
                        entry, dir_fd, depth=depth, max_depth=max_depth
                    )
                    if outcome is None:
                        continue
                    if outcome.is_file:
                        yield dir_fd, entry.name, rel_name
                    else:
                        assert outcome.sub_fd is not None
                        stack.append((outcome.sub_fd, rel_name, depth + 1))
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
    max_line_chars: int = DEFAULT_MAX_LINE_CHARS,
    max_output_bytes: int = DEFAULT_GREP_MAX_OUTPUT_BYTES,
) -> dict[str, Any]:
    """Search for the substring *pattern* in files under *relative* (recursive, capped).

    Never descends into or reads through a symlink (see module docstring).
    Binary files (content that cannot be decoded as UTF-8) are skipped
    without raising. Stops as soon as any of *max_files* files scanned,
    *max_matches* total matches, or *max_output_bytes* of (already
    per-line-truncated) snippet text is reached -- ``truncated`` tells the
    caller a cap was hit, though not which one.

    Every count-based cap is clamped to its documented hard limit regardless
    of what the caller asks for (issue #3) -- previously only the *default*
    values were enforced, not a ceiling on a caller-supplied override.

    Each match's line text is truncated to *max_line_chars* (issue #5): a
    single long line -- a minified JS/JSON file, say -- would otherwise make
    one "match" arbitrarily large, and *max_matches* alone still allows up
    to ``max_matches * max_line_chars`` bytes back, hence the separate
    *max_output_bytes* budget on top of it.

    Matches are grouped by file: ``{"files": [{"path", "match_count",
    "matches": [{"line_number", "line", "truncated"}]}], "files_scanned",
    "total_matches", "truncated"}`` -- compacter than a flat list that
    repeats "path" on every match, and lets a caller often skip a follow-up
    fs_read entirely.
    """
    max_files = min(max(max_files, 1), MAX_GREP_MAX_FILES)
    max_matches = min(max(max_matches, 1), MAX_GREP_MAX_MATCHES)
    max_matches_per_file = min(
        max(max_matches_per_file, 1), MAX_GREP_MAX_MATCHES_PER_FILE
    )
    max_depth = min(max(max_depth, 1), MAX_GREP_MAX_DEPTH)
    max_line_chars = max(max_line_chars, 1)
    max_output_bytes = max(max_output_bytes, 1)

    files: list[dict[str, Any]] = []
    files_scanned = 0
    total_matches = 0
    output_bytes = 0
    truncated = False

    def _budget_exhausted() -> bool:
        return (
            files_scanned >= max_files
            or total_matches >= max_matches
            or output_bytes >= max_output_bytes
        )

    for dir_fd, name, rel_path in _iter_files_no_follow(
        root, relative, max_depth=max_depth
    ):
        if _budget_exhausted():
            truncated = True
            break
        files_scanned += 1

        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
        except OSError:
            continue

        file_matches: list[dict[str, Any]] = []
        with os.fdopen(fd, "rb") as fh:
            for line_number, raw_line in enumerate(fh, start=1):
                if len(file_matches) >= max_matches_per_file or _budget_exhausted():
                    truncated = True
                    break
                try:
                    line = raw_line.decode("utf-8")
                except UnicodeDecodeError:
                    break  # treat as binary; skip the rest of this file
                if pattern not in line:
                    continue
                text = line.rstrip("\n")
                line_truncated = len(text) > max_line_chars
                if line_truncated:
                    text = text[:max_line_chars]
                file_matches.append(
                    {
                        "line_number": line_number,
                        "line": text,
                        "truncated": line_truncated,
                    }
                )
                total_matches += 1
                output_bytes += len(text.encode("utf-8"))

        if file_matches:
            files.append(
                {
                    "path": rel_path,
                    "match_count": len(file_matches),
                    "matches": file_matches,
                }
            )

        if _budget_exhausted():
            truncated = True
            break

    return {
        "path": relative,
        "pattern": pattern,
        "files": files,
        "files_scanned": files_scanned,
        "total_matches": total_matches,
        "truncated": truncated,
    }


__all__ = [
    "PathEscapeError",
    "grep_files",
    "list_dir",
    "read_file",
    "stat_path",
]
