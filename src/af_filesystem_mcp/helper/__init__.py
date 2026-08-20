"""The impersonated helper: everything in this package runs AS the requesting user.

``af_filesystem_mcp.helper.ops`` holds the pure, privilege-agnostic
filesystem operations; ``python -m af_filesystem_mcp.helper`` (see
``__main__.py``) is the tiny JSON-over-stdio CLI that
``af_filesystem_mcp.impersonate.run_helper`` launches per call, started
running under the caller's real uid/gid via
``asyncio.create_subprocess_exec(..., user=..., group=...)``.
"""

from __future__ import annotations
