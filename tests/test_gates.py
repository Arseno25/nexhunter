"""The 4-gate finding validator: verdict parsing and aggregation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest

from nexhunter.findings.gates import (
    CONFIDENCE_DEDUCTIONS,
    GATE_NAMES,
    GateStatus,
    GateVerdict,
    aggregate,
    confidence_score,
    gateable,
    notes_from,
    parse_verdicts,
    report_depth,
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
    print("[TEST] UNSURE with no FAIL/DEMOTE -> NEEDS_REVIEW...")
    assert aggregate(_verdicts(reachability=GateVerdict.UNSURE)) == GateStatus.NEEDS_REVIEW
    print("  [OK]")


def test_demote_without_fail_demotes():
    print("[TEST] DEMOTE with no FAIL -> DEMOTED, not rejected...")
    assert aggregate(_verdicts(trigger=GateVerdict.DEMOTE)) == GateStatus.DEMOTED
    print("  [OK]")


def test_fail_outranks_demote():
    print("[TEST] a FAIL still refutes even alongside a DEMOTE...")
    assert aggregate(_verdicts(refutation=GateVerdict.FAIL, trigger=GateVerdict.DEMOTE)) == GateStatus.REFUTED
    print("  [OK]")


def test_demote_outranks_unsure():
    print("[TEST] DEMOTE takes priority over UNSURE -- a known caveat beats unresolved evidence...")
    assert aggregate(_verdicts(reachability=GateVerdict.UNSURE, trigger=GateVerdict.DEMOTE)) == GateStatus.DEMOTED
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


def test_confidence_score_no_flags_is_full():
    print("[TEST] no deduction flags -> confidence 100...")
    assert confidence_score({}) == 100
    print("  [OK]")


def test_confidence_score_deducts_only_true_flags():
    print("[TEST] confidence_score subtracts only flags marked true...")
    score = confidence_score({"partial_attack_path": True, "bounded_impact": False, "requires_user_interaction": True})
    assert score == 100 - CONFIDENCE_DEDUCTIONS["partial_attack_path"] - CONFIDENCE_DEDUCTIONS["requires_user_interaction"]
    print("  [OK]")


def test_confidence_score_ignores_unknown_keys():
    print("[TEST] confidence_score never invents a deduction for an unknown key...")
    assert confidence_score({"made_up_flag": True}) == 100
    print("  [OK]")


def test_confidence_score_clamped_at_zero():
    print("[TEST] confidence_score never goes negative...")
    all_true = dict.fromkeys(CONFIDENCE_DEDUCTIONS, True)
    assert confidence_score(all_true) == max(0, 100 - sum(CONFIDENCE_DEDUCTIONS.values()))
    assert confidence_score(all_true) >= 0
    print("  [OK]")


def test_report_depth_thresholds():
    print("[TEST] report_depth: >=80 full, 60-79 partial, <60 lead...")
    assert report_depth(100) == "full"
    assert report_depth(80) == "full"
    assert report_depth(79) == "partial"
    assert report_depth(60) == "partial"
    assert report_depth(59) == "lead"
    assert report_depth(0) == "lead"
    print("  [OK]")


def test_report_depth_unscored_is_full():
    print("[TEST] never-scored (None) does not get penalized -> full...")
    assert report_depth(None) == "full"
    print("  [OK]")
