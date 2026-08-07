"""Sanity check for the curated bug-bounty hunting reference (findings/patterns.py).

Content, not logic -- this just guards against the lists/dicts silently
going empty or picking up a non-string entry, since nothing else in the
type system would catch that."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.findings.patterns import (
    ALWAYS_REJECTED,
    ATTACK_VECTORS,
    COMMON_FALSE_POSITIVES,
    FRAMEWORK_ANTIPATTERNS,
    IMPACT_TIERS,
    SAFE_PATTERNS,
    SEVERITY_ESCALATION,
    UNIVERSAL_PATTERNS,
)


def test_reference_lists_are_non_empty_strings():
    print("[TEST] ALWAYS_REJECTED, SAFE_PATTERNS, UNIVERSAL_PATTERNS are non-empty string tuples...")
    for name, items in (
        ("ALWAYS_REJECTED", ALWAYS_REJECTED),
        ("SAFE_PATTERNS", SAFE_PATTERNS),
        ("UNIVERSAL_PATTERNS", UNIVERSAL_PATTERNS),
    ):
        assert isinstance(items, tuple) and items, f"{name} must be a non-empty tuple"
        assert all(isinstance(item, str) and item.strip() for item in items), f"{name} has a non-string/empty entry"
    print("  [OK]")


def test_no_duplicate_entries():
    print("[TEST] no duplicate entries within any flat list...")
    for name, items in (
        ("ALWAYS_REJECTED", ALWAYS_REJECTED),
        ("SAFE_PATTERNS", SAFE_PATTERNS),
        ("UNIVERSAL_PATTERNS", UNIVERSAL_PATTERNS),
    ):
        assert len(items) == len(set(items)), f"{name} has a duplicate entry"
    print("  [OK]")


def test_attack_vectors_categories_are_non_empty_string_tuples():
    print("[TEST] ATTACK_VECTORS: every category is a non-empty tuple of strings...")
    assert isinstance(ATTACK_VECTORS, dict) and ATTACK_VECTORS
    for category, vectors in ATTACK_VECTORS.items():
        assert isinstance(category, str) and category
        assert isinstance(vectors, tuple) and vectors, f"category {category!r} has no vectors"
        assert all(isinstance(v, str) and v.strip() for v in vectors), f"category {category!r} has a bad entry"
    print(f"  [OK] {len(ATTACK_VECTORS)} categories")


def test_framework_antipatterns_are_non_empty_string_tuples():
    print("[TEST] FRAMEWORK_ANTIPATTERNS: every framework is a non-empty tuple of strings...")
    assert isinstance(FRAMEWORK_ANTIPATTERNS, dict) and FRAMEWORK_ANTIPATTERNS
    for framework, items in FRAMEWORK_ANTIPATTERNS.items():
        assert isinstance(framework, str) and framework
        assert isinstance(items, tuple) and items, f"framework {framework!r} has no anti-patterns"
        assert all(isinstance(i, str) and i.strip() for i in items)
    print(f"  [OK] {len(FRAMEWORK_ANTIPATTERNS)} frameworks")


def test_common_false_positives_have_pattern_and_reality():
    print("[TEST] COMMON_FALSE_POSITIVES: every entry has pattern + reality...")
    assert isinstance(COMMON_FALSE_POSITIVES, tuple) and COMMON_FALSE_POSITIVES
    for entry in COMMON_FALSE_POSITIVES:
        assert isinstance(entry, dict)
        assert set(entry) == {"pattern", "reality"}
        assert entry["pattern"].strip() and entry["reality"].strip()
    print(f"  [OK] {len(COMMON_FALSE_POSITIVES)} false-positive patterns")


def test_severity_escalation_is_non_empty_string_map():
    print("[TEST] SEVERITY_ESCALATION: non-empty dict of string -> string...")
    assert isinstance(SEVERITY_ESCALATION, dict) and SEVERITY_ESCALATION
    for objection, counter in SEVERITY_ESCALATION.items():
        assert isinstance(objection, str) and objection.strip()
        assert isinstance(counter, str) and counter.strip()
    print(f"  [OK] {len(SEVERITY_ESCALATION)} escalation counters")


def test_impact_tiers_are_ordered_and_well_formed():
    print("[TEST] IMPACT_TIERS: 5 tiers T0-T4, each with the required fields...")
    assert len(IMPACT_TIERS) == 5
    expected_order = ["T0", "T1", "T2", "T3", "T4"]
    assert [tier["tier"] for tier in IMPACT_TIERS] == expected_order
    for entry in IMPACT_TIERS:
        assert set(entry) == {"tier", "meaning", "examples", "severity_floor"}
        assert all(str(v).strip() for v in entry.values())
    print("  [OK]")


if __name__ == "__main__":
    print("\n=== Patterns Tests ===\n")
    test_reference_lists_are_non_empty_strings()
    test_no_duplicate_entries()
    test_attack_vectors_categories_are_non_empty_string_tuples()
    test_framework_antipatterns_are_non_empty_string_tuples()
    test_common_false_positives_have_pattern_and_reality()
    test_severity_escalation_is_non_empty_string_map()
    test_impact_tiers_are_ordered_and_well_formed()
    print("\n=== All Patterns Tests Passed ===\n")
