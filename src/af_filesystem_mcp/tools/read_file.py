"""fs_read: read a file under the caller's own AF home or data area."""

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


class FsReadResult(BaseModel):
    """Structured result of ``fs_read``."""

    root: Literal["home", "data"]
    path: str
    content: str
    truncated: bool
    size: int


def register(mcp: MCPServer) -> None:
    """Register the fs_read tool."""

    @mcp.tool(
        annotations=ToolAnnotations(
            title="Read file",
            read_only_hint=True,
            open_world_hint=False,
        )
    )
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
    ) -> Annotated[CallToolResult, FsReadResult]:
        """Read a file under your own AF home or data area.

        `root` selects "home" (`/home/<you>`) or "data" (`/data/<you>`);
        `path` is relative to it. `mode` controls how much of the file
        comes back:

        - "bytes" (default): bytes `[offset, offset+length)`, capped at a
          server-configured window (64 KiB by default, 256 KiB hard limit
          even if you ask for more). A bare call with no `offset`/`length`
          on a file bigger than the server's whole-file-read limit is
          refused with an error naming the real size -- use "tail"/"head"/
          "lines", or "bytes" with an explicit `offset`/`length`, instead.
        - "head"/"tail": the first/last `num_lines` lines. "tail" is the
          file's real tail, not the tail of whatever fit in one window.
        - "lines": `num_lines` lines starting at `start_line` (0-based),
          reachable anywhere in the file.

        The result always reports the file's real `size` alongside
        `content`, so you can tell a small page of a huge file apart from
        "this is the whole file". Content is decoded as UTF-8 with invalid
        bytes replaced -- this is a text-reading tool, not a binary dump. A
        symlink is never followed: reading one fails with a clear error
        rather than silently reading whatever it points at (see fs_stat to
        see a symlink's target).
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
            shown_bytes = len(result["content"].encode("utf-8"))
            output += (
                f"\n\n[... truncated: showing {shown_bytes} of "
                f"{result['size']} bytes ...]"
            )
        text = append_next_actions(
            output,
            [
                "Use `fs_read` again with a different `offset`/`start_line` to see more.",
            ],
        )
        payload = FsReadResult(root=root, **result)
        return CallToolResult(
            content=[TextContent(type="text", text=text)],
            structured_content=payload.model_dump(mode="json"),
        )
