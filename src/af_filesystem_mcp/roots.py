"""Server-wide configuration for where the two per-user confinement roots live."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RootsConfig:
    """The two root *prefixes* every caller's per-user roots are built under.

    Not the per-user roots themselves -- see ``af_filesystem_mcp.paths.
    UserRoots.for_unixname``, which appends the caller's own ``unixname`` to
    each of these. Defaults match the AF's real mount points
    (``nfs.af.uchicago.edu:/export/home`` at ``/home``; the Ceph-backed
    data area at ``/data`` -- see maniaclab/af-mcp-platform#188).
    """

    home_root: Path = Path("/home")
    data_root: Path = Path("/data")
