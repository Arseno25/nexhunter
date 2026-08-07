"""The 4-gate finding validator: verdict parsing and aggregation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest

from nexhunter.findings.gates import (
    GATE_NAMES,
    GateStatus,
    GateVerdict,
    aggregate,
    gateable,
    notes_from,
    parse_verdicts,
)


def _verdicts(**overrides) -> dict[str, GateVerdict]:
    base = {name: GateVerdict.PASS for name in GATE_NAMES}
    base.update(overrides)
    return base


def test_all_pass_confirms():
    print("[TEST] all four gates PASS -> CONFIRMED...")
    assert aggregate(_verdicts()) == GateStatus.CONFIRMED
    print("  [OK]")


def test_any_fail_refutes_even_with_other_passes():
    print("[TEST] one FAIL refutes regardless of the other three...")
    assert aggregate(_verdicts(trigger=GateVerdict.FAIL)) == GateStatus.REFUTED
    assert aggregate(_verdicts(refutation=GateVerdict.FAIL, impact=GateVerdict.UNSURE)) == GateStatus.REFUTED
    print("  [OK]")


def test_unsure_without_fail_needs_review():
    print("[TEST] UNSURE with no FAIL -> NEEDS_REVIEW...")
    assert aggregate(_verdicts(reachability=GateVerdict.UNSURE)) == GateStatus.NEEDS_REVIEW
    print("  [OK]")


def test_parse_verdicts_accepts_case_insensitive_strings():
    print("[TEST] parse_verdicts accepts mixed-case string verdicts...")
    verdicts = parse_verdicts({"refutation": "Pass", "reachability": "FAIL", "trigger": "unsure", "impact": "pass"})
    assert verdicts["refutation"] == GateVerdict.PASS
    assert verdicts["reachability"] == GateVerdict.FAIL
    assert verdicts["trigger"] == GateVerdict.UNSURE
    print("  [OK]")


def test_parse_verdicts_reports_missing_gate():
    print("[TEST] parse_verdicts names the missing gate...")
    with pytest.raises(ValueError, match="impact"):
        parse_verdicts({"refutation": "pass", "reachability": "pass", "trigger": "pass"})
    print("  [OK]")


def test_parse_verdicts_rejects_unknown_value():
    print("[TEST] parse_verdicts rejects a value outside pass/fail/unsure...")
    with pytest.raises(ValueError):
        parse_verdicts({"refutation": "maybe", "reachability": "pass", "trigger": "pass", "impact": "pass"})
    print("  [OK]")


def test_notes_from_defaults_to_empty_string():
    print("[TEST] notes_from fills in '' for any gate without a *_notes field...")
    notes = notes_from({"refutation_notes": "blocked by WAF rule 42"})
    assert notes == {"refutation": "blocked by WAF rule 42", "reachability": "", "trigger": "", "impact": ""}
    print("  [OK]")


def test_gateable_only_true_for_vulnerability_claims():
    print("[TEST] gateable() mirrors Finding.is_vulnerability...")
    assert gateable(True) is True
    assert gateable(False) is False
    print("  [OK]")
