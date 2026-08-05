"""Shared fixtures.

The test modules are written to run two ways: directly (`python tests/x.py`)
for a quick loop, and under pytest in CI. The directly-run entry points pass a
temporary directory positionally, so the same parameter names are provided
here as fixtures.
"""

import sys
from pathlib import Path

import pytest

# Allow `import nexhunter...` when the package is not pip-installed.
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


@pytest.fixture
def base(tmp_path: Path) -> Path:
    """Temporary working directory, named for the execution-layer tests."""
    return tmp_path


@pytest.fixture
def tmp(tmp_path: Path) -> Path:
    """Temporary working directory, named for the service and CLI tests."""
    return tmp_path
