"""CVSS 3.1 base score calculator."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest

from nexhunter.findings.cvss import score_vector, try_score_vector


def test_known_critical_vector():
    print("[TEST] canonical critical vector scores 9.8...")
    r = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert r.base_score == 9.8
    assert r.severity == "critical"
    print("  [OK]")


def test_scope_changed_maxes_at_ten():
    print("[TEST] scope-changed all-high caps at 10.0...")
    r = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert r.base_score == 10.0
    print("  [OK]")


def test_no_impact_scores_zero():
    print("[TEST] zero impact metrics score 0.0, severity info...")
    r = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert r.base_score == 0.0
    assert r.severity == "info"
    print("  [OK]")


def test_low_severity_vector():
    print("[TEST] low-impact local vector scores 1.8...")
    r = score_vector("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
    assert r.base_score == 1.8
    assert r.severity == "low"
    print("  [OK]")


def test_case_insensitive_and_normalizes_order():
    print("[TEST] lowercase input accepted, output normalized to canonical order...")
    r = score_vector("cvss:3.1/i:h/av:n/s:u/c:h/pr:n/a:h/ac:l/ui:n")
    assert r.base_score == 9.8
    assert r.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    print("  [OK]")


@pytest.mark.parametrize(
    "bad_vector",
    [
        "",
        "not a vector",
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # wrong CVSS version
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # invalid AV value
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:1",  # unknown metric
    ],
)
def test_malformed_vector_raises(bad_vector):
    print(f"[TEST] malformed vector rejected: {bad_vector!r}...")
    with pytest.raises(ValueError):
        score_vector(bad_vector)
    assert try_score_vector(bad_vector) is None
    print("  [OK]")
