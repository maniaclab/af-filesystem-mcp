"""Tests for local (stdio) identity resolution."""

from __future__ import annotations

import os
import pwd

from af_filesystem_mcp.auth.local import local_identity


def test_local_identity_matches_current_process() -> None:
    identity = local_identity()
    assert identity.uid == os.getuid()
    assert identity.gid == os.getgid()
    assert identity.unixname == pwd.getpwuid(os.getuid()).pw_name
