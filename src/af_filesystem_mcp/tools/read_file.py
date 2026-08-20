"""fs_read: read a file under the caller's own AF home or data area."""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.mcpserver import Context, MCPServer  # noqa: TC002

from af_filesystem_mcp.tools._helpers import (
    append_next_actions,
    call_fs_op,
    format_error,
)


def register(mcp: MCPServer) -> None:
    @mcp.tool()
    async def fs_read(
        root: Literal["home", "data"],
        path: str,
        mode: Literal["bytes", "head", "tail", "lines"] = "bytes",
        offset: int = 0,
        length: int | None = None,
        start_line: int = 0,
        num_lines: int = 200,
        *,
        ctx: Context[Any, Any],
    ) -> str:
        """Read a file under your own AF home or data area.

        `root` selects "home" (`/home/<you>`) or "data" (`/data/<you>`);
        `path` is relative to it. `mode` controls how much of the file
        comes back:

        - "bytes" (default): bytes `[offset, offset+length)`, capped at 1
          MiB per call (8 MiB hard limit even if you ask for more).
        - "head"/"tail": the first/last `num_lines` lines.
        - "lines": `num_lines` lines starting at `start_line` (0-based).

        Content is decoded as UTF-8 with invalid bytes replaced -- this is
        a text-reading tool, not a binary dump. A symlink is never
        followed: reading one fails with a clear error rather than
        silently reading whatever it points at (see fs_stat to see a
        symlink's target).
        """
        try:
            result = await call_fs_op(
                ctx,
                "read",
                root,
                path,
                mode=mode,
                offset=offset,
                length=length,
                start_line=start_line,
                num_lines=num_lines,
            )
        except Exception as exc:  # noqa: BLE001
            return format_error(
                exc,
                hints=[
                    "Use `fs_stat` to confirm the path exists and is a regular file.",
                ],
            )
        output = result["content"]
        if result["truncated"]:
            output += "\n\n[... truncated ...]"
        return append_next_actions(
            output,
            [
                "Use `fs_read` again with a different `offset`/`start_line` to see more.",
            ],
        )
