"""Per-call orchestration glue shared by every fs_* tool.

``call_fs_op`` is the one path every tool goes through: resolve the
caller's ``Identity`` (broker or local mode, see
``af_filesystem_mcp.auth``), build their two confinement roots (see
``af_filesystem_mcp.paths.UserRoots``), select one of them, acquire a
per-user concurrency slot, and run the requested operation in the
impersonated helper subprocess (``af_filesystem_mcp.impersonate``).
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any, Literal

from mcp.types import CallToolResult, TextContent

from af_filesystem_mcp.budgets import Budgets
from af_filesystem_mcp.impersonate import (
    HelperError,
    HelperTimeoutError,
    run_helper_json,
)
from af_filesystem_mcp.paths import UserRoots

if TYPE_CHECKING:
    from pathlib import Path

    from af_filesystem_mcp.identity import Identity

#: Which of the caller's two confinement roots a tool call targets.
RootName = Literal["home", "data"]

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_CONCURRENT_CALLS_PER_USER = 4

#: helper-op kwarg -> Budgets field, per op. Lets call_fs_op inject the
#: server-configured per-call budgets into the helper payload without each
#: tool module reaching into the lifespan context itself -- helper.ops runs
#: in a subprocess, so these can't just be read there the way timeout_seconds
#: is read in-process. Injected via setdefault, so an explicit caller-supplied
#: kwarg (as in a direct call_fs_op test, or a future tool parameter) always
#: wins; the ops-layer MAX_* clamps remain the actual enforcement regardless
#: of what a Budgets value requests.
_OP_BUDGETS: dict[str, dict[str, str]] = {
    "read": {"max_bytes": "read_max_bytes", "max_file_size": "read_max_file_size"},
    "grep": {
        "max_output_bytes": "grep_max_output_bytes",
        "max_line_chars": "max_line_chars",
    },
}

#: Friendly, LLM-facing context for each tag af_filesystem_mcp.helper.__main__
#: writes to stderr (see that module's docstring for the tag contract).
_HELPER_TAG_HINTS: dict[str, str] = {
    "PATH_ESCAPE": "That path is outside your confined home/data directory.",
    "NOT_FOUND": "No such file or directory.",
    "IS_A_DIRECTORY": "That path is a directory, not a file.",
    "NOT_A_DIRECTORY": "That path is not a directory.",
    "PERMISSION_DENIED": "Permission denied for that path.",
    "INVALID_ARGUMENT": "Invalid argument.",
}


async def resolve_context(ctx: Any) -> tuple[Identity, UserRoots]:
    """Resolve the caller's ``Identity`` and per-user confinement roots for this call.

    Reads ``identity_resolver`` (an async ``Callable[[ctx], Identity]``,
    e.g. ``af_filesystem_mcp.auth.broker.resolve_identity`` bound to a
    verifier, or a trivial wrapper around
    ``af_filesystem_mcp.auth.local.local_identity`` in stdio mode) and
    ``roots_config`` (a ``RootsConfig``) from
    ``ctx.request_context.lifespan_context`` -- populated by
    ``af_filesystem_mcp.server`` at startup.
    """
    lifespan = ctx.request_context.lifespan_context
    identity: Identity = await lifespan["identity_resolver"](ctx)
    roots_config = lifespan["roots_config"]
    roots = UserRoots.for_unixname(
        identity.unixname,
        home_root=roots_config.home_root,
        data_root=roots_config.data_root,
    )
    return identity, roots


def _select_root(roots: UserRoots, root: str) -> Path:
    # `str`, not `RootName`, on purpose: MCP tool parameters are declared
    # with the narrower Literal type for the LLM-facing schema, but nothing
    # enforces that at the transport boundary, so the ValueError branch
    # below is real, reachable defensive code (see read_file's identical
    # reasoning in helper/ops.py).
    if root == "home":
        return roots.home
    if root == "data":
        return roots.data
    msg = f"invalid root {root!r}: must be 'home' or 'data'"
    raise ValueError(msg)


def _get_semaphore(lifespan: dict[str, Any], unixname: str) -> asyncio.Semaphore:
    """Return (creating if needed) the per-unixname concurrency semaphore.

    Caps how many filesystem calls one user can have in flight at once --
    a runaway ``fs_grep`` over a large tree should degrade that one user's
    own throughput, not everyone else's NFS RTT.
    """
    semaphores: dict[str, asyncio.Semaphore] = lifespan.setdefault("_semaphores", {})
    if unixname not in semaphores:
        limit = lifespan.get(
            "max_concurrent_calls_per_user", DEFAULT_MAX_CONCURRENT_CALLS_PER_USER
        )
        semaphores[unixname] = asyncio.Semaphore(limit)
    return semaphores[unixname]


async def call_fs_op(
    ctx: Any,
    op: str,
    root: RootName,
    path: str,
    **kwargs: Any,
) -> dict[str, Any]:
    """Run *op* (``"list"``/``"stat"``/``"read"``/``"grep"``) against *path* under *root*.

    *root* selects between the caller's two confinement roots ("home" or
    "data"); *path* is relative to it. Extra *kwargs* are forwarded
    verbatim to the corresponding ``af_filesystem_mcp.helper.ops`` function
    as its JSON payload (e.g. ``offset``/``limit`` for list, ``pattern``
    for grep) -- for ``"read"``/``"grep"``, any budget field *op* accepts
    (see ``_OP_BUDGETS``) not already present in *kwargs* is filled in from
    the lifespan's configured ``Budgets`` (or ``Budgets()``'s defaults, if
    the lifespan carries none).

    Raises:
        ValueError: *root* is neither ``"home"`` nor ``"data"``.
        HelperError, HelperTimeoutError: see ``af_filesystem_mcp.impersonate``.
        PermissionError, IdentityError: see ``af_filesystem_mcp.auth.broker``.
    """
    identity, roots = await resolve_context(ctx)
    chosen_root = _select_root(roots, root)

    lifespan = ctx.request_context.lifespan_context
    semaphore = _get_semaphore(lifespan, identity.unixname)
    timeout = lifespan.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    budgets: Budgets = lifespan.get("budgets", Budgets())

    for kwarg_name, budget_field in _OP_BUDGETS.get(op, {}).items():
        kwargs.setdefault(kwarg_name, getattr(budgets, budget_field))

    payload = {"root": str(chosen_root), "relative": path, **kwargs}
    async with semaphore:
        result: dict[str, Any] = await run_helper_json(
            [op, json.dumps(payload)],
            uid=identity.uid,
            gid=identity.gid,
            timeout=timeout,
        )
    return result


def format_error(exc: Exception, *, hints: list[str] | None = None) -> CallToolResult:
    """Format *exc* as an LLM-facing ``is_error`` result, never raising.

    ``HelperError``'s ``"TAG: detail"`` contract (see
    ``af_filesystem_mcp.helper.__main__``) is parsed to attach a friendly,
    plain-English prefix; an unrecognized tag (a helper contract change
    this module hasn't been updated for) falls back to the raw message
    rather than hiding it. No ``structured_content`` is set: an error
    result carries no structured payload (mcp SDK's ``convert_result``
    only validates ``structured_content`` against the tool's output
    model when ``is_error`` is false).
    """
    if isinstance(exc, HelperTimeoutError):
        message = f"Error: the filesystem operation timed out ({exc})."
    elif isinstance(exc, HelperError):
        tag, sep, detail = str(exc).partition(": ")
        prefix = _HELPER_TAG_HINTS.get(tag) if sep else None
        message = f"Error: {prefix} ({detail})" if prefix else f"Error: {exc}"
    else:
        message = f"Error: {exc}"
    text = append_next_actions(message, hints or [])
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=True)


def append_next_actions(output: str, actions: list[str]) -> str:
    """Append a bulleted "Next actions" section to *output*, or return it unchanged if *actions* is empty."""
    if not actions:
        return output
    bullets = "\n".join(f"- {action}" for action in actions)
    return f"{output}\n\nNext actions:\n{bullets}"
