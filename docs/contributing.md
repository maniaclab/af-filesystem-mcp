---
icon: lucide/code
---

# Contributing

## Architecture

```
LLM <--MCP/stdio or HTTP--> af-filesystem-mcp serve --exec(setuid/setgid)--> impersonated helper subprocess --syscalls--> NFS home / Ceph data
```

Every filesystem operation for user _alice_ runs in a short-lived helper
subprocess started running as alice's real uid/gid
(`asyncio.create_subprocess_exec(..., user=uid, group=gid)`), never inside the
long-lived async server process itself. The kernel — and, for the NFS-mounted
homes, the NFS server — enforces every permission check against the real
identity, so a bug in this server's own path-pinning logic can only let alice
reach what alice's real uid could already reach. See `CLAUDE.md` § "Security
model" for the full rationale, including the two additional layers of path
confinement (`resolve_confined`, `secure_open_confined`) that exist as policy
hygiene on top of that boundary.

The tool surface is deliberately small and read-only in v1: `fs_list`,
`fs_stat`, `fs_read`, `fs_grep` — no write, delete, rename, chmod, or
command-execution tool anywhere in this package.

## Development setup

```bash
git clone https://github.com/maniaclab/af-filesystem-mcp
cd af-filesystem-mcp
pixi install
pixi run pre-commit-install
```

## Build and test commands

```bash
pixi run test          # quick tests (no privilege needed)
pixi run test-slow     # all tests including any marked slow/root_only
pixi run lint          # pre-commit + pylint
pixi run helm-lint     # lint + smoke-render the Helm chart
pixi run build         # build sdist + wheel
```

## Tests

- `tests/test_paths.py` — path confinement: traversal, symlink escapes
- `tests/test_secure_open.py` — `secure_open_confined`: the O_NOFOLLOW walk
- `tests/test_impersonate.py` — impersonation subprocess wiring (mocked)
- `tests/auth/` — local and broker identity resolution
- `tests/helper/` — `helper/ops.py` and the `__main__` CLI
- `tests/tools/` — the four MCP tools, end-to-end through the real (but
  unimpersonated in the test sandbox) helper subprocess

`tests/conftest.py` provides `mock_ctx` and `fs_roots` fixtures (real `tmp_path`
roots), so tool tests exercise the actual helper subprocess without needing root
privilege.

See `CLAUDE.md` for the full design rationale, the tool registration pattern for
adding a new tool, and the Helm chart layout used for deployment.
