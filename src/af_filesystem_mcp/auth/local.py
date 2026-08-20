"""Local (stdio) identity: the caller already *is* the server process's own uid/gid.

There is exactly one caller in stdio mode, so no impersonation happens or
is needed -- ``af_filesystem_mcp.impersonate.run_helper`` already skips the
``user=``/``group=`` subprocess kwargs whenever the server process is not
running as root, which is always true here (nothing about stdio mode runs
as root). Every fs_* call is confined to this identity's own ``$HOME`` and
a configured local data root, exactly as if the caller ran the helper
directly themselves.
"""

from __future__ import annotations

import os
import pwd

from af_filesystem_mcp.identity import Identity


def local_identity() -> Identity:
    """Return the current process's own identity as an ``Identity``."""
    uid = os.getuid()
    gid = os.getgid()
    unixname = pwd.getpwuid(uid).pw_name
    return Identity(uid=uid, gid=gid, unixname=unixname)
