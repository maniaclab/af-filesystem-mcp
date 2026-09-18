"""fs_stat: metadata for one path under the caller's own AF home or data area."""

from __future__ import annotations

import stat
from datetime import datetime, timezone
from typing import Any, Literal

from mcp.server.mcpserver import Context, MCPServer  # noqa: TC002
from mcp.types import CallToolResult, TextContent

from af_filesystem_mcp.tools._helpers import (
    append_next_actions,
    call_fs_op,
    format_error,
)


def _format_stat(result: dict[str, Any]) -> str:
    lines = [
        f"path: {result['path'] or '.'}",
        f"type: {result['type']}",
    ]
    if result["type"] == "symlink":
        lines.append(f"target: {result.get('target')}")
    if result["size"] is not None:
        lines.append(f"size: {result['size']}B")
    lines.append(
        f"mtime: {datetime.fromtimestamp(result['mtime'], tz=timezone.utc).isoformat()}"
    )
    if "mode" in result:
        lines.append(f"mode: {stat.filemode(result['mode'])} ({oct(result['mode'])})")
    return "\n".join(lines)


def register(mcp: MCPServer) -> None:
    """Register the fs_stat tool."""

    @mcp.tool()
    async def fs_stat(
        root: Literal["home", "data"],
        path: str = "",
        *,
        ctx: Context[Any, Any],
    ) -> CallToolResult:
        """Get metadata (type, size, mtime, permissions) for one path.

        `root` selects which of your two confined areas to look in: "home"
        (`/home/<you>`) or "data" (`/data/<you>`). `path` is relative to
        that root ("" for the root itself). A symlink is reported as such,
        with its literal target string -- never followed or dereferenced.
        """
        try:
            result = await call_fs_op(ctx, "stat", root, path)
        except Exception as exc:  # noqa: BLE001
            return format_error(
                exc, hints=["Use `fs_list` on the parent directory to check the name."]
            )
        output = _format_stat(result)
        text = append_next_actions(
            output,
            [
                "Use `fs_read` if this is a file you want the contents of.",
                "Use `fs_list` if this is a directory you want to browse.",
            ],
        )
        return CallToolResult(content=[TextContent(type="text", text=text)])
