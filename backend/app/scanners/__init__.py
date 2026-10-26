"""Scanner implementations, one per data source.

Adding a source that touches a real website requires legal review first (docs/05-legal-compliance.md).
This package ships only the local-fixture scanner.
"""

from ..config import get_settings
from ..services import Scanner
from .fixture import FixtureScanner


def build_scanners() -> list[Scanner]:
    path = get_settings().fixture_scanner_path
    return [FixtureScanner(path)] if path else []
