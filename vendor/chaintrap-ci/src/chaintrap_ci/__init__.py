"""Chaintrap CI — discover pinned packages from lockfiles and run runner-local scans."""

from chaintrap_ci.discover import discover, discover_packages
from chaintrap_ci.scan import ScanConfig, evaluate_scan_rollup, run_local_scan

__all__ = [
    "discover",
    "discover_packages",
    "ScanConfig",
    "evaluate_scan_rollup",
    "run_local_scan",
]
__version__ = "0.2.0"