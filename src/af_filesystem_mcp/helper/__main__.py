"""``python -m af_filesystem_mcp.helper <op> <json-payload>``.

The process ``af_filesystem_mcp.impersonate.run_helper`` launches per call,
running under the caller's real uid/gid in production (see
``af_filesystem_mcp.impersonate`` and ``af_filesystem_mcp.helper.ops``).

Contract: exactly two argv entries -- an operation name (``list``, ``stat``,
``read``, or ``grep``) and a single JSON object string carrying that
operation's keyword arguments, always including ``root`` (a filesystem
path) and ``relative`` (the path within it, ``""`` for the root itself).
On success, the operation's JSON-serializable result dict is written to
stdout and the process exits 0. On failure, a single ``TAG: message`` line
is written to stderr and the process exits 1 -- the tag lets
``af_filesystem_mcp.tools`` classify the failure (path escape vs. not found
vs. a generic error) without parsing prose, mirroring ami-mcp/rucio-mcp's
``classify_error``/``format_error`` pattern at their own client boundaries.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from af_filesystem_mcp.helper import ops
from af_filesystem_mcp.paths import PathEscapeError

if TYPE_CHECKING:
    from collections.abc import Callable

_OPS: dict[str, Callable[..., dict[str, Any]]] = {
    "list": ops.list_dir,
    "stat": ops.stat_path,
    "read": ops.read_file,
    "grep": ops.grep_files,
}

# Order matters: more specific OSError subclasses must be checked before
# the generic fallback. PathEscapeError is checked ahead of OSError too --
# it is a plain Exception, not an OSError subclass, so order does not
# strictly matter for it, but keeping it first documents that it is the
# highest-signal case.
_ERROR_TAGS: tuple[tuple[type[BaseException], str], ...] = (
    (PathEscapeError, "PATH_ESCAPE"),
    (FileNotFoundError, "NOT_FOUND"),
    (IsADirectoryError, "IS_A_DIRECTORY"),
    (NotADirectoryError, "NOT_A_DIRECTORY"),
    (PermissionError, "PERMISSION_DENIED"),
    (ValueError, "INVALID_ARGUMENT"),
)


def _tag_for(exc: BaseException) -> str:
    for exc_type, tag in _ERROR_TAGS:
        if isinstance(exc, exc_type):
            return tag
    return "ERROR"


def _fail(tag: str, message: str) -> None:
    sys.stderr.write(f"{tag}: {message}\n")
    sys.exit(1)


def main(argv: list[str] | None = None) -> None:
    """Entry point: parse *argv* (default ``sys.argv[1:]``), run, print, exit."""
    argv = sys.argv[1:] if argv is None else argv

    if len(argv) != 2:
        _fail("ERROR", "usage: python -m af_filesystem_mcp.helper <op> <json-payload>")
        return

    op_name, payload_json = argv
    handler = _OPS.get(op_name)
    if handler is None:
        _fail("ERROR", f"unknown operation: {op_name!r}")
        return

    try:
        payload = json.loads(payload_json)
    except json.JSONDecodeError as exc:
        _fail("ERROR", f"invalid JSON payload: {exc}")
        return

    if not isinstance(payload, dict) or "root" not in payload:
        _fail("ERROR", "payload must be a JSON object with a 'root' key")
        return

    root = Path(payload.pop("root"))
    relative = payload.pop("relative", "")

    try:
        result = handler(root, relative, **payload)
    except Exception as exc:  # noqa: BLE001 - subprocess boundary: must never crash uncaught
        _fail(_tag_for(exc), str(exc))
        return

    sys.stdout.write(json.dumps(result))


if __name__ == "__main__":
    main()
