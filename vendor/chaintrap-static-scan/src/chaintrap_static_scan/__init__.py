"""OSV-only static inventory scanner for npm and PyPI."""

from chaintrap_static_scan.models import OsvFinding, PackageKey
from chaintrap_static_scan.pipeline import scan_packages

__all__ = ["OsvFinding", "PackageKey", "scan_packages", "__version__"]

__version__ = "0.1.0"
