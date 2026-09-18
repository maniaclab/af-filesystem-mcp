"""fs_list: list a directory under the caller's own AF home or data area."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from mcp.server.mcpserver import Context, MCPServer  # noqa: TC002
from mcp.types import CallToolResult, TextContent

from af_filesystem_mcp.tools._helpers import (
    append_next_actions,
    call_fs_op,
    format_error,
)


def _format_entry(entry: dict[str, Any]) -> str:
    entry_type = entry["type"]
    name = entry["name"] + ("/" if entry_type == "dir" else "")
    if entry_type == "symlink":
        return f"  [symlink] {name} -> {entry.get('target')}"
    size = f"{entry['size']}B" if entry["size"] is not None else "-"
    mtime = datetime.fromtimestamp(entry["mtime"], tz=timezone.utc).isoformat()
    return f"  [{entry_type}] {size:>10}  {mtime}  {name}"


def _format_listing(result: dict[str, Any], *, root: str, path: str) -> str:
    header = f"{root}:{path or '.'} ({result['total']} entries)"
    if not result["entries"]:
        return f"{header}\n  (empty)"
    lines = [header, *[_format_entry(e) for e in result["entries"]]]
    if result["truncated"]:
        shown = result["offset"] + len(result["entries"])
        lines.append(
            f"  ... truncated, showing {result['offset']}-{shown} of {result['total']}"
        )
    return "\n".join(lines)


def register(mcp: MCPServer) -> None:
    """Register the fs_list tool."""

    @mcp.tool()
    async def fs_list(
        root: Literal["home", "data"],
        path: str = "",
        offset: int = 0,
        limit: int = 1000,
        *,
        ctx: Context[Any, Any],
    ) -> CallToolResult:
        """List the entries of a directory under your own AF home or data area.

        `root` selects which of your two confined areas to browse:
        "home" (your NFS home, `/home/<you>`) or "data" (your Ceph data
        area, `/data/<you>`). `path` is relative to that root ("" for the
        root itself). Symlinks are listed by name and target but never
        followed. Results are paginated via `offset`/`limit` (capped at
        5000 entries per call).
        """
        try:
            result = await call_fs_op(
                ctx, "list", root, path, offset=offset, limit=limit
            )
        except Exception as exc:  # noqa: BLE001
            return format_error(
                exc,
                hints=[
                    "Use `fs_stat` to check whether the path exists and what type it is."
                ],
            )
        output = _format_listing(result, root=root, path=path)
        text = append_next_actions(
            output,
            [
                "Use `fs_read` to read a file's contents.",
                "Use `fs_stat` for details on one entry.",
                "Use `fs_grep` to search file contents under this directory.",
            ],
        )
        return CallToolResult(content=[TextContent(type="text", text=text)])
