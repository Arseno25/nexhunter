"""Sanity check for the curated do-not-report reference (findings/patterns.py).

Content, not logic -- this just guards against the lists silently going
empty or picking up a non-string entry, since nothing else in the type
system would catch that."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.findings.patterns import ALWAYS_REJECTED, SAFE_PATTERNS


def test_reference_lists_are_non_empty_strings():
    print("[TEST] ALWAYS_REJECTED and SAFE_PATTERNS are non-empty string tuples...")
    for name, items in (("ALWAYS_REJECTED", ALWAYS_REJECTED), ("SAFE_PATTERNS", SAFE_PATTERNS)):
        assert isinstance(items, tuple) and items, f"{name} must be a non-empty tuple"
        assert all(isinstance(item, str) and item.strip() for item in items), f"{name} has a non-string/empty entry"
    print("  [OK]")


def test_no_duplicate_entries():
    print("[TEST] no duplicate entries within either list...")
    assert len(ALWAYS_REJECTED) == len(set(ALWAYS_REJECTED))
    assert len(SAFE_PATTERNS) == len(set(SAFE_PATTERNS))
    print("  [OK]")


if __name__ == "__main__":
    print("\n=== Patterns Tests ===\n")
    test_reference_lists_are_non_empty_strings()
    test_no_duplicate_entries()
    print("\n=== All Patterns Tests Passed ===\n")
