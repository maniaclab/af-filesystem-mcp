"""Server-wide configuration for the per-call token/byte budgets fs_read and fs_grep enforce.

One dataclass, mirroring ``af_filesystem_mcp.roots.RootsConfig``, so there is
a single place to learn -- and a single place to configure, from the CLI down
to the Helm chart's ``limits.*`` values -- every bound a caller's fs_read or
fs_grep call is subject to. Defaults reference ``af_filesystem_mcp.helper.ops``'s
own constants rather than restating the numbers, so a server-configured
default and the helper's clamp ceiling cannot drift apart the way the fs_grep
docstring and its unenforced caps did (issue #3).

``call_fs_op`` (``af_filesystem_mcp.tools._helpers``) is what actually reads
this: it maps each op name to the ``Budgets`` fields relevant to it and
injects them into the JSON payload sent to the impersonated helper
subprocess, since ``helper/ops.py`` runs there, not in this process.
"""

from __future__ import annotations

from dataclasses import dataclass

from af_filesystem_mcp.helper import ops


@dataclass(frozen=True)
class Budgets:
    """Per-call ceilings for fs_read/fs_grep, tunable per deployment.

    ``helper.ops``'s own ``MAX_*`` constants are the actual enforcement (a
    ``Budgets`` value above a ceiling is clamped there, exactly like any
    other caller-supplied argument) -- this is the server operator's chosen
    *default/requested* value, not a second source of truth for the ceiling
    itself.
    """

    read_max_bytes: int = ops.DEFAULT_READ_BYTES_LIMIT
    read_max_file_size: int = ops.DEFAULT_MAX_READ_FILE_SIZE
    grep_max_output_bytes: int = ops.DEFAULT_GREP_MAX_OUTPUT_BYTES
    max_line_chars: int = ops.DEFAULT_MAX_LINE_CHARS
