# af-filesystem-mcp v0.1.2

<!-- --8<-- [start:intro] -->

An MCP server that gives an AF (Analysis Facility) user browse/read access to
their own files on the AF's shared NFS home (`/home/<unixname>`) and Ceph data
area (`/data/<unixname>`) — nothing more. Designed to sit behind
af-mcp-platform's credential broker so an LLM session can look at a user's own
analysis outputs, condor logs, and scratch files without a human copying paths
around.

<!-- --8<-- [end:intro] -->

<!-- --8<-- [start:what-it-does] -->

## What it does

- **List** a directory (`fs_list`)
- **Read** a file, by byte range or line range, including head/tail (`fs_read`)
- **Stat** a path — size, mtime, type, permissions (`fs_stat`)
- **Grep** for a pattern across files under a directory, capped in files scanned
  and matches returned (`fs_grep`)

That is the entire v1 tool surface. There is deliberately no write tool, no
delete, no chmod, no arbitrary command execution, and no full-tree walk
(directory-size, duplicate-finder). See `CLAUDE.md` for the design rationale and
phase-2 (write) plan.

<!-- --8<-- [end:what-it-does] -->

<!-- --8<-- [start:security-model] -->

## Security model

Every filesystem operation for user _alice_ runs in a short-lived helper
subprocess **impersonating alice's real uid/gid** — the server process itself
(running as root, holding only `CAP_SETUID`/`CAP_SETGID`) never reads or writes
a byte of user data directly. This means the kernel (and, for the NFS-mounted
homes, the NFS server) enforces every permission check against the real
identity: even a bug in this server's own path-pinning logic can only let alice
reach what alice's real uid could already reach. See `CLAUDE.md` § "Security
model" and `src/af_filesystem_mcp/paths.py` for the full design rationale, and
[maniaclab/af-mcp-platform#188](https://github.com/maniaclab/af-mcp-platform/issues/188)
for the workplan and the (rejected) alternatives this design was chosen over.

<!-- --8<-- [end:security-model] -->

<!-- --8<-- [start:installation] -->

## Installation

```bash
pip install af-filesystem-mcp
```

Or with pixi:

```bash
pixi add af-filesystem-mcp
```

<!-- --8<-- [end:installation] -->

## Requirements

- Python 3.10+
- Linux (the impersonation mechanism is POSIX `setuid`/`setgid`; there is no
  Windows/macOS deployment target — local `stdio` mode runs fine on any OS for
  development, since it never impersonates)

<!-- --8<-- [start:usage] -->

## Quick start (local development, stdio)

In `stdio` mode there is exactly one caller (you), so no impersonation happens —
the server operates directly as your own uid/gid, confined to your own `$HOME`
and a configurable data root:

```bash
af-filesystem-mcp serve --data-root /data
```

## Broker mode (production, HTTP)

```bash
af-filesystem-mcp serve --transport http \
  --broker-url https://mcp.af.uchicago.edu \
  --broker-audience af-filesystem-mcp \
  --home-root /home --data-root /data
```

Bearers are broker-issued identity JWTs (`aud=af-filesystem-mcp`) carrying
`uid`/`gid`/`unixname` POSIX claims (af-mcp-platform's
`identityProviders[].targetOptions.af-filesystem-mcp.includePosix: true`).
Requires the `broker` extra: `pip install af-filesystem-mcp[broker]`.

<!-- --8<-- [end:usage] -->

## Development

```bash
pixi install
pixi run test
pixi run lint
```

See `CLAUDE.md` for architecture, the impersonation/path-confinement design, and
conventions for adding a new tool.
