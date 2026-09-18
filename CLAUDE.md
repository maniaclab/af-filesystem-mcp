# af-filesystem-mcp — Contributor Guide

MCP server that gives an AF (Analysis Facility) user browse/read access to their
own files on the AF's shared NFS home (`/home/<unixname>`) and Ceph data area
(`/data/<unixname>`) — nothing more. Read-only in v1: there is no write, delete,
rename, or command-execution tool anywhere in this package.

Companion backends in the same af-mcp-platform: [ami-mcp][ami-mcp] (AMI
metadata) and [rucio-mcp][rucio-mcp] (Rucio data management). This repo follows
their conventions (tool naming, broker-mode auth, Helm chart shape) wherever
they apply, and departs from them explicitly where this backend's job is
different — see "How this differs from ami-mcp/rucio-mcp" below.

[ami-mcp]: https://github.com/kratsg/ami-mcp
[rucio-mcp]: https://github.com/kratsg/rucio-mcp

## Origin

Designed in [maniaclab/af-mcp-platform#188][188], which also has the full design
rationale and the (rejected) alternative — an off-the-shelf
`rust-mcp-filesystem` server — and why it was rejected: stdio-only (no per-user
identity), and a dangling-symlink write-escape via a validate-then-open TOCTOU.
This package exists specifically to not have either problem.

[188]: https://github.com/maniaclab/af-mcp-platform/issues/188

## Security model

**The security boundary is impersonation, not path-string validation.** Every
filesystem operation for user _alice_ runs in a short-lived helper subprocess
that is started running AS alice's real uid/gid
(`asyncio.create_subprocess_exec(..., user=uid, group=gid)`), never inside the
long-lived async server process itself (which would mean a process-wide
`seteuid()` racing across concurrently in-flight requests for different users).
This means the kernel — and, for the NFS-mounted homes, the NFS server —
enforces every permission check against the real identity: even a bug in this
server's own path-pinning logic can only let alice reach what alice's real uid
could already reach. This mirrors [voms-token-service][voms-token-service]'s
`minting.py` impersonation pattern, adapted from `subprocess.run` to
`asyncio.create_subprocess_exec`.

[voms-token-service]: https://github.com/maniaclab/voms-token-service

On top of that boundary, two layers of path confinement exist as policy hygiene
/ prompt-injection containment (not the boundary itself — see
`src/af_filesystem_mcp/paths.py`'s module docstring):

- `resolve_confined(root, relative)`: a string-level check, before any I/O, that
  fully resolves symlinks (`Path.resolve(strict=False)`, so a dangling symlink's
  literal target is what gets checked — never falling back to checking only the
  symlink's own parent directory the way rust-mcp-filesystem's `validate_path`
  did) and confirms the result is still under `root`.
- `secure_open_confined(root, relative, flags)`: closes the TOCTOU window a
  string-level check alone leaves open. It walks `root` → target one path
  component at a time via `os.open(part, ..., dir_fd=parent_fd, O_NOFOLLOW)` —
  an openat-style walk where _every_ component, intermediate or final, fails
  outright (`ELOOP`) if it turns out to be a symlink at the moment it is
  actually opened, rather than being silently followed. This is the direct fix
  for rust-mcp-filesystem's actual vulnerability class.

`fs_read`/`fs_grep` (content-touching ops) always use `secure_open_confined` and
refuse to follow **any** symlink, even one that points to another file within
the same confined root — a deliberately conservative v1 restriction (see
`helper/ops.py`'s module docstring for why, and what it would take to loosen
it). `fs_list`/`fs_stat` (metadata-only, `lstat`-based, never dereferenced) use
the more permissive `resolve_confined`, since reporting a symlink's name and
literal target string never discloses file contents.

Unlike voms-token-service, this server needs **no `CAP_DAC_READ_SEARCH`**:
voms-token-service has exactly one code path (reading `~/.globus/*.pem`) where
root reads a user's file directly, before impersonating, and that capability is
what makes that one read work. af-filesystem-mcp has no such path at all — every
single byte of user data this server ever touches goes through the impersonated
subprocess. The container's capability set is `SETUID`+`SETGID` only (see
`charts/af-filesystem-mcp/values.yaml`'s `containerSecurityContext`).

## Project layout

```
src/af_filesystem_mcp/
├── __init__.py, _version.pyi, py.typed
├── cli.py             # argparse: `af-filesystem-mcp serve`
├── server.py          # stdio (local identity) + broker-mode HTTP transport
├── identity.py        # Identity(uid, gid, unixname) -- what every call impersonates
├── roots.py            # RootsConfig: the /home, /data prefix roots
├── paths.py            # resolve_confined, secure_open_confined, UserRoots
├── impersonate.py      # run_helper/run_helper_json: per-call impersonated subprocess
├── budgets.py          # Budgets: fs_read/fs_grep per-call token/byte ceilings
├── auth/
│   ├── local.py         # stdio mode: the server process's own uid/gid
│   └── broker.py        # HTTP mode: broker-issued JWT -> Identity
├── helper/
│   ├── __main__.py       # `python -m af_filesystem_mcp.helper <op> <json>` CLI
│   └── ops.py             # list_dir/stat_path/read_file/grep_files (pure functions)
└── tools/
    ├── _helpers.py        # call_fs_op, format_error, append_next_actions
    ├── list_dir.py        # fs_list
    ├── stat_path.py        # fs_stat
    ├── read_file.py        # fs_read
    └── grep_files.py       # fs_grep
tests/
├── conftest.py                # mock_ctx, fs_roots fixtures (real tmp_path roots)
├── test_paths.py              # path confinement: traversal, symlink escapes
├── test_secure_open.py        # secure_open_confined: the O_NOFOLLOW walk
├── test_impersonate.py        # impersonation subprocess wiring (mocked, like
│                               # voms-token-service's own test pattern)
├── test_server.py, test_cli.py
├── auth/                       # local + broker identity resolution
├── helper/                     # ops.py + the __main__ CLI
└── tools/                      # the four MCP tools, end-to-end through the
                                 # real (non-impersonating-in-this-sandbox)
                                 # helper subprocess -- see test_helpers.py's
                                 # module docstring
```

## How this differs from ami-mcp/rucio-mcp

- **No shared-secret HTTP mode.** ami-mcp/rucio-mcp's shared-secret mode serves
  one pre-authenticated identity behind a static bearer. For this backend that
  identity IS a uid/gid — a shared secret would mean every caller impersonates
  the _same_ fixed user, which defeats the entire point of per-user filesystem
  access. HTTP transport is broker-only.
- **No credential redeem step.** ami-mcp/rucio-mcp's broker mode verifies a
  broker-issued JWT and then redeems a _separate_ credential (a VOMS proxy) at
  the broker per call. This backend's bearer already carries everything it needs
  — the `uid`/`gid`/`unixname` POSIX claims — so there is no redeem call. See
  `auth/broker.py`'s module docstring for why `resolve_identity` re-verifies the
  same bearer a second time (the mcp SDK's `TokenVerifier` adapter discards
  POSIX claims by design).
- **No "client" object.** ami-mcp/rucio-mcp tools call a client method
  (`pyAMI.client.Client`, `rucio.client.Client`). This backend's equivalent is
  `af_filesystem_mcp.tools._helpers.call_fs_op`, which runs the impersonated
  helper subprocess instead of a network call.

## Tool registration pattern

Same shape as ami-mcp/rucio-mcp: each `tools/*.py` module exports
`register(mcp: MCPServer) -> None`; `server.py` calls `register(mcp)` for every
module in `_register_all`. Tools are closures inside `register()` using the
`@mcp.tool()` decorator.

Every tool returns markdown _and_ structured content:
`CallToolResult(content=[...], structured_content=...)`, with the return
annotation spelled `Annotated[CallToolResult, ResultModel]`. This is the escape
hatch the mcp SDK's `func_metadata()` provides specifically for this case (see
`mcp/server/mcpserver/utilities/func_metadata.py`): annotating a tool
`-> ResultModel` directly gets you `outputSchema` + `structuredContent`, but the
SDK then renders the text block as `pydantic_core.to_json(result, indent=2)`,
destroying the curated markdown. `Annotated[CallToolResult, ResultModel]`
publishes `outputSchema` from `ResultModel`, validates `structured_content`
against it at runtime, and returns the `CallToolResult` — markdown text block
and all — unchanged.

```python
# tools/mymodule.py
from __future__ import annotations

from typing import Annotated, Any, Literal

from mcp.server.mcpserver import Context, MCPServer  # noqa: TC002 (needed at runtime for eval_str signature introspection)
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import BaseModel

from af_filesystem_mcp.tools._helpers import append_next_actions, call_fs_op, format_error


class FsMyToolResult(BaseModel):
    """Structured result of fs_my_tool."""

    root: Literal["home", "data"]
    path: str
    # ... the rest of the fields call_fs_op's result dict already carries


def register(mcp: MCPServer) -> None:
    @mcp.tool(
        annotations=ToolAnnotations(
            title="My tool",
            read_only_hint=True,
            open_world_hint=False,
        )
    )
    async def fs_my_tool(
        root: Literal["home", "data"],
        path: str = "",
        *,
        ctx: Context[Any, Any],
    ) -> Annotated[CallToolResult, FsMyToolResult]:
        """Tool description -- shown to the LLM as the tool's purpose."""
        try:
            result = await call_fs_op(ctx, "my_op", root, path)
        except Exception as exc:  # noqa: BLE001
            return format_error(exc, hints=["..."])
        text = append_next_actions(str(result), ["..."])
        payload = FsMyToolResult(root=root, **result)
        return CallToolResult(
            content=[TextContent(type="text", text=text)],
            structured_content=payload.model_dump(mode="json"),
        )
```

Key conventions:

- Tool names are prefixed with `fs_` to avoid collisions.
- `ctx` is keyword-only (after `*`).
- `Context`/`MCPServer`/`CallToolResult`/`TextContent`/`ToolAnnotations` and
  every result model used in a return annotation must be imported as **real,
  non-`TYPE_CHECKING`** imports (with a `# noqa: TC002` on the
  `mcp.server.mcpserver` import to satisfy ruff's type-checking-import lint) —
  the mcp SDK's `func_metadata()` calls
  `inspect.signature(func, eval_str=True)`, which needs every name in the
  signature to actually resolve in the function's module globals at _runtime_,
  not just for static type checking. Getting this wrong raises
  `InvalidSignature: Unable to evaluate type annotations` the moment the tool is
  registered.
- All four tools are read-only and confined to the caller's own two AF roots, so
  every `ToolAnnotations` today is `read_only_hint=True, open_world_hint=False`.
  `destructive_hint`/`idempotent_hint` stay unset — the spec says they're only
  meaningful when `read_only_hint` is false.
- Errors are returned via `format_error(exc, hints=[...])`, which itself returns
  a `CallToolResult(is_error=True)` — never raised, never a bare
  `f"Error: {exc}"` string, and never a plain error `CallToolResult` built by
  hand at a tool's own call site.
- `except Exception as exc:` lines carry `# noqa: BLE001` inline;
  `broad-exception-caught` is disabled globally in pylint (`pyproject.toml`).
- Use `append_next_actions(output, [...])` to suggest follow-up tool calls, on
  the markdown text going into the `TextContent` block -- never on
  `structured_content`.
- If adding a new _operation_ (not just a new tool wrapping existing ops), add
  the pure function to `helper/ops.py`, wire it into `helper/__main__ .py`'s
  `_OPS` dict, and give it its own `PathEscapeError`/`OSError` handling
  consistent with the existing four.

Then wire it in `server.py`:

```python
from af_filesystem_mcp.tools import mymodule

for _module in [..., mymodule]:
    _module.register(mcp)
```

## Adding a new tool

1. Decide whether it's a new _tool_ over an existing op, or needs a new op in
   `helper/ops.py` (see "Tool registration pattern" above).
2. Add a new `@mcp.tool()` function inside the module's `register()`.
3. If creating a new module, add it to `_register_all` in `server.py`.
4. Write unit tests: `helper/ops.py` logic directly (no privilege needed — see
   `tests/helper/test_ops.py`); the tool itself via `mock_ctx`/`fs_roots` from
   `tests/conftest.py` (real subprocess, not privileged in tests, so it runs
   unimpersonated exactly like stdio mode — see `tests/tools/test_helpers.py`'s
   module docstring for why that is a legitimate near-end-to-end test, not a
   shortcut).
5. Run `pixi run test` to verify.

## Build and test commands

```bash
pixi run test          # quick tests (no privilege needed)
pixi run test-slow     # all tests including any marked slow/root_only
pixi run lint          # pre-commit + pylint
pixi run helm-lint     # lint + smoke-render the Helm chart
pixi run build         # build sdist + wheel
```

## Development setup

```bash
pixi install
pixi run pre-commit-install
```

## Server transports

- **stdio** (default): single caller, the process's own uid/gid
  (`auth/ local.py`). No impersonation happens or is needed. Confined to the
  real `$HOME` and a `--data-root` you provide.
- **http, broker mode** (the only HTTP mode):
  `af-filesystem-mcp serve --transport http --broker-url <url> --broker-audience af-filesystem-mcp`.
  Bearers are broker-issued identity JWTs (see af-mcp-platform's
  `identityProviders[].targetOptions.af-filesystem-mcp.includePosix: true`)
  verified via `af-credentials` (the `broker` extra:
  `pip install af-filesystem-mcp[broker]`).

## Deployment (Helm chart)

`charts/af-filesystem-mcp/` mirrors ami-mcp's chart shape (pixi-install init
container, same label/helper conventions), with two AF-specific additions:

- Two read-only PVC mounts (`homes.existingClaim` at `/home`,
  `data.existingClaim` at `/data`) — the chart does not create the underlying
  PV; that is a sibling flux_apps manifest, exactly voms-token-service's
  `pv-homes.yaml`/`pvc-homes.yaml` pattern. See `values.yaml`'s comments on
  `homes`/`data` for what each PVC needs to bind to, and the **known open
  question** on `data`: the only observed `/data` convention on the AF today (a
  node-level hostPath mount used by htcondor execute pods, e.g.
  `/data/projects`) is not confirmed to expose a real per-user
  `/data/<unixname>` tree the way the NFS homes export does for
  `/home/<unixname>` — verify before deploying.
- `containerSecurityContext` adds only `SETUID`/`SETGID` (see "Security model"
  above for why not `DAC_READ_SEARCH` too).

## Non-goals (v1)

- No write, delete, rename, chmod, or any mutating tool.
- No arbitrary command execution (no shell, no sandboxed exec) — the tool
  surface is deliberately the smallest useful set for "browse/read your own
  files": `fs_list`, `fs_stat`, `fs_read`, `fs_grep`. A general-purpose
  sandboxed shell was considered and rejected (see #188): it would need the same
  impersonation/path-confinement machinery this package already has, plus
  resource-limiting and auditability work an explicit, capped tool API gets for
  free from having a fixed, enumerable set of operations.
- No full-tree operations (directory size, duplicate-finder, recursive copy) —
  `fs_grep` is the one recursive op, and it is capped in files scanned and
  matches returned.

Phase 2 (writes) is deferred by design, not by a disabled flag: there is no
`fs_write`/`fs_edit` code in this repository at all yet. When it is built, it
should ship behind an explicit, separately gated capability (a Helm value and/or
a distinct broker capability), soak-tested against the read-only v1 in
production first, and reuse `secure_open_confined` with `O_CREAT`/`O_EXCL`
semantics rather than a new path-resolution mechanism.
