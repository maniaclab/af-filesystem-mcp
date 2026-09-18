"""fs_grep: search file contents under the caller's own AF home or data area."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from mcp.server.mcpserver import Context, MCPServer  # noqa: TC002
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import BaseModel

from af_filesystem_mcp.tools._helpers import (
    append_next_actions,
    call_fs_op,
    format_error,
)


class FsGrepMatch(BaseModel):
    """One matching line within a file, as reported by ``fs_grep``.

    ``line`` is truncated to the server's per-line character budget (see
    ``truncated``) -- a single long line (e.g. a minified JS/JSON file)
    would otherwise make one "match" arbitrarily large.
    """

    line_number: int
    line: str
    truncated: bool


class FsGrepFileMatches(BaseModel):
    """All matches found within one file, as reported by ``fs_grep``."""

    path: str
    match_count: int
    matches: list[FsGrepMatch]


class FsGrepResult(BaseModel):
    """Structured result of ``fs_grep``, grouped by file.

    Grouped rather than a flat per-match list (each carrying its own
    ``path``) so the common case -- several matches in the same file --
    doesn't repeat that file's path once per match, and a caller can often
    skip a follow-up ``fs_read`` entirely.
    """

    root: Literal["home", "data"]
    path: str
    pattern: str
    files: list[FsGrepFileMatches]
    files_scanned: int
    total_matches: int
    truncated: bool


def _format_matches(result: dict[str, Any]) -> str:
    header = (
        f"{result['files_scanned']} file(s) scanned, "
        f"{result['total_matches']} match(es) for {result['pattern']!r}"
    )
    if not result["files"]:
        return header
    lines = [header]
    for file_matches in result["files"]:
        lines.append(
            f"  {file_matches['path']} ({file_matches['match_count']} matches)"
        )
        lines.extend(
            f"    {m['line_number']}: {m['line']}" for m in file_matches["matches"]
        )
    if result["truncated"]:
        lines.append("  ... truncated (hit a files-scanned/matches/output-size cap)")
    return "\n".join(lines)


def register(mcp: MCPServer) -> None:
    """Register the fs_grep tool."""

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Search file contents",
            read_only_hint=True,
            open_world_hint=False,
        )
    )
    async def fs_grep(
        root: Literal["home", "data"],
        pattern: str,
        path: str = "",
        max_files: int = 500,
        max_matches: int = 200,
        *,
        ctx: Context[Any, Any],
    ) -> Annotated[CallToolResult, FsGrepResult]:
        """Search for a literal substring across files under a directory (recursive).

        `root` selects "home" (`/home/<you>`) or "data" (`/data/<you>`);
        `path` is the directory to search under (relative, "" for the
        whole root). `pattern` is matched as a plain substring per line
        (not a regex). Capped at `max_files` files scanned (hard limit
        500) and `max_matches` total matches (hard limit 200) -- if either
        cap is hit the result says so; narrow `path` and retry rather than
        raising the caps for a broad search. Never descends into or reads
        through a symlink; binary files are skipped. Results are grouped
        by file, and each matched line is truncated to a server-configured
        character budget (long lines are cut short, not the match count).
        """
        try:
            result = await call_fs_op(
                ctx,
                "grep",
                root,
                path,
                pattern=pattern,
                max_files=max_files,
                max_matches=max_matches,
            )
        except Exception as exc:  # noqa: BLE001
            return format_error(
                exc,
                hints=[
                    "Use `fs_list` to confirm the directory exists and check its size."
                ],
            )
        output = _format_matches(result)
        text = append_next_actions(
            output,
            [
                "Use `fs_read` to see more context around a match.",
                "Narrow `path` to a subdirectory if the result was truncated.",
            ],
        )
        payload = FsGrepResult(root=root, **result)
        return CallToolResult(
            content=[TextContent(type="text", text=text)],
            structured_content=payload.model_dump(mode="json"),
        )
