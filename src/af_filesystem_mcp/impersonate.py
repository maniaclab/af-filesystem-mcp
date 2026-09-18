"""Per-call impersonated subprocess execution -- the actual security boundary.

Every filesystem operation for a given caller runs in a short-lived helper
subprocess (``python -m af_filesystem_mcp.helper <op> <json-args>``) that is
started running AS that caller's real uid/gid via
``asyncio.create_subprocess_exec(..., user=uid, group=gid, extra_groups=...)``.
This deliberately does **not** ``os.seteuid()``/``os.setegid()`` inside the
long-lived async server process itself: that call is process-wide and would
race across concurrently in-flight requests for different users sharing the
same event loop. A fresh subprocess per call has no such race — each one
carries exactly one identity for its entire (short) life — at the cost of
~10-30ms of spawn overhead per call, irrelevant next to LLM round-trip
latency and NFS RTT (maniaclab/af-mcp-platform#188).

This mirrors voms-token-service's ``minting.py`` impersonation pattern
(subprocess held to the requesting uid/gid so the kernel, and the NFS
server, enforce every permission check against the real identity) adapted
from ``subprocess.run`` to ``asyncio.create_subprocess_exec`` so the async
MCP server's event loop is never blocked waiting on the helper.

Outside a privileged deployment (``os.geteuid() != 0`` — local dev, unit
tests, or ``stdio`` transport where the caller already *is* the target
uid/gid) no impersonation is attempted or needed, exactly like
voms-token-service's ``mint_proxy``.
"""

from __future__ import annotations

# `as os`/`as asyncio` (PEP 484's explicit-reexport self-import) rather than a
# plain import: tests monkeypatch these as module attributes
# (impersonate.os.geteuid, impersonate.asyncio.create_subprocess_exec), which
# mypy's implicit-reexport check otherwise flags as accessing an unexported
# name from outside the module. ruff's PLC0414 and pylint's useless-import-
# alias both consider the same syntax a no-op alias, so both are suppressed
# here -- the linters disagree with mypy, mypy wins.
import asyncio as asyncio  # noqa: PLC0414  # pylint: disable=useless-import-alias
import json
import os as os  # noqa: PLC0414  # pylint: disable=useless-import-alias
import sys
from typing import Any

#: Defense-in-depth ceiling on a single call's stdout (issue #5): the real
#: bound on memory/tokens is each op's own budget in helper.ops, enforced
#: before the helper ever writes a byte -- this just catches a bug in that
#: layer (or a future op that forgets its budget) before an implausibly
#: large result is handed to the LLM. Far above any legitimate op output
#: under the current budgets (fs_read maxes out at MAX_READ_BYTES_LIMIT,
#: fs_grep at DEFAULT_GREP_MAX_OUTPUT_BYTES plus JSON overhead).
#:
#: This check runs *after* `proc.communicate()` returns, so it is a
#: post-hoc guard, not a streaming one: the memory for an oversized stdout
#: is already spent by the time this fires. Streaming enforcement would
#: mean hand-rolling a chunked read with a running total plus a concurrent
#: stderr drain (to avoid deadlocking on a full pipe buffer) -- a lot of
#: machinery for a guard whose job is catching a bug that should never
#: happen, not for bounding memory under normal operation.
MAX_HELPER_STDOUT_BYTES = 4 * 1_048_576  # 4 MiB


class HelperTimeoutError(Exception):
    """Raised when the helper subprocess exceeds its wall-clock budget."""


class HelperError(Exception):
    """Raised when the helper subprocess exits non-zero, or its output is unusable.

    The message is the helper's stderr (or a generic fallback) -- the helper
    itself is responsible for never writing anything security-sensitive
    (raw file contents, other users' paths) to stderr.
    """


async def run_helper(
    argv: list[str],
    *,
    uid: int,
    gid: int,
    timeout: float,
    extra_groups: list[int] | None = None,
) -> bytes:
    """Run the filesystem helper subprocess and return its raw stdout bytes.

    *argv* is passed after ``-m af_filesystem_mcp.helper`` verbatim (never
    through a shell) -- by convention ``[op, json_payload]``, see
    ``af_filesystem_mcp.helper.__main__``.

    Raises:
        HelperTimeoutError: if the helper does not complete within *timeout*
            seconds; the process is killed (not just abandoned) before the
            error is raised.
        HelperError: if the helper exits non-zero.
    """
    kwargs: dict[str, Any] = {}
    if os.geteuid() == 0:
        kwargs["user"] = uid
        kwargs["group"] = gid
        kwargs["extra_groups"] = extra_groups if extra_groups is not None else []

    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "af_filesystem_mcp.helper",
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        **kwargs,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        msg = f"filesystem helper timed out after {timeout}s running {argv[:1]!r}"
        raise HelperTimeoutError(msg) from None

    if proc.returncode != 0:
        detail = stderr.decode(errors="replace").strip()
        msg = detail or f"filesystem helper exited {proc.returncode}"
        raise HelperError(msg)

    if len(stdout) > MAX_HELPER_STDOUT_BYTES:
        msg = (
            f"filesystem helper produced {len(stdout)} bytes of stdout, "
            f"over the {MAX_HELPER_STDOUT_BYTES}-byte limit"
        )
        raise HelperError(msg)

    return stdout


async def run_helper_json(
    argv: list[str],
    *,
    uid: int,
    gid: int,
    timeout: float,
    extra_groups: list[int] | None = None,
) -> Any:
    """Like ``run_helper``, but parse stdout as JSON.

    Raises:
        HelperError: also when the helper's stdout is not valid JSON --
            treated as a helper-contract violation, not a caller error.
    """
    stdout = await run_helper(
        argv, uid=uid, gid=gid, timeout=timeout, extra_groups=extra_groups
    )
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        msg = f"filesystem helper produced non-JSON output: {exc}"
        raise HelperError(msg) from exc
