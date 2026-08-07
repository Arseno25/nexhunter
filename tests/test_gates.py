"""The 4-gate finding validator: verdict parsing and aggregation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest

from nexhunter.findings.gates import (
    CONFIDENCE_DEDUCTIONS,
    GATE_NAMES,
    PRESUBMISSION_NAMES,
    PROMOTABLE_FROM,
    SEVERITY_ADJUSTMENTS,
    Disposition,
    GateStatus,
    GateVerdict,
    adjust_severity_rank,
    aggregate,
    confidence_score,
    disposition,
    gateable,
    notes_from,
    parse_presubmission,
    parse_verdicts,
    presubmission_ready,
    promotable,
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


def test_disposition_confirmed_high_confidence_stays_confirmed():
    print("[TEST] CONFIRMED at >=60 confidence stays confirmed...")
    assert disposition(GateStatus.CONFIRMED, 80) == Disposition.CONFIRMED
    assert disposition(GateStatus.CONFIRMED, None) == Disposition.CONFIRMED
    print("  [OK]")


def test_disposition_confirmed_low_confidence_becomes_lead():
    print("[TEST] CONFIRMED below 60 confidence becomes LEAD...")
    assert disposition(GateStatus.CONFIRMED, 59) == Disposition.LEAD
    assert disposition(GateStatus.DEMOTED, 0) == Disposition.LEAD
    print("  [OK]")


def test_disposition_refuted_ignores_confidence():
    print("[TEST] REFUTED stays refuted regardless of confidence...")
    assert disposition(GateStatus.REFUTED, 100) == Disposition.REFUTED
    assert disposition(GateStatus.REFUTED, None) == Disposition.REFUTED
    print("  [OK]")


def test_disposition_needs_review_ignores_confidence():
    print("[TEST] NEEDS_REVIEW is not eligible for LEAD -- it's already unsettled...")
    assert disposition(GateStatus.NEEDS_REVIEW, 10) == Disposition.NEEDS_REVIEW
    print("  [OK]")


def test_disposition_unreviewed_passthrough():
    print("[TEST] UNREVIEWED passes through unchanged...")
    assert disposition(GateStatus.UNREVIEWED, None) == Disposition.UNREVIEWED
    print("  [OK]")


def test_adjust_severity_rank_no_flags_unchanged():
    print("[TEST] no severity-adjustment flags -> rank unchanged...")
    assert adjust_severity_rank(4, {}) == 4
    print("  [OK]")


def test_adjust_severity_rank_deducts_per_true_flag():
    print("[TEST] adjust_severity_rank subtracts one rank per true flag...")
    assert adjust_severity_rank(4, {"timing_dependent": True}) == 3
    assert adjust_severity_rank(4, {"timing_dependent": True, "requires_large_capital": True}) == 2
    print("  [OK]")


def test_adjust_severity_rank_ignores_unknown_keys():
    print("[TEST] adjust_severity_rank never invents a deduction for an unknown key...")
    assert adjust_severity_rank(4, {"made_up": True}) == 4
    print("  [OK]")


def test_adjust_severity_rank_floors_at_zero():
    print("[TEST] adjust_severity_rank never goes negative...")
    all_true = dict.fromkeys(SEVERITY_ADJUSTMENTS, True)
    assert adjust_severity_rank(1, all_true) == 0
    assert adjust_severity_rank(0, all_true) == 0
    print("  [OK]")


def _presubmission(**overrides) -> dict:
    payload = dict.fromkeys(PRESUBMISSION_NAMES, True)
    payload.update(overrides)
    return payload


def test_parse_presubmission_accepts_full_checklist():
    print("[TEST] parse_presubmission accepts a complete checklist...")
    checklist = parse_presubmission(_presubmission())
    assert all(checklist.values())
    print("  [OK]")


def test_parse_presubmission_reports_missing_item():
    print("[TEST] parse_presubmission names the missing checklist item...")
    payload = _presubmission()
    del payload["deduplication_checked"]
    with pytest.raises(ValueError, match="deduplication_checked"):
        parse_presubmission(payload)
    print("  [OK]")


def test_presubmission_ready_requires_all_true():
    print("[TEST] presubmission_ready is True only when every item is true...")
    assert presubmission_ready(_presubmission()) is True
    assert presubmission_ready(_presubmission(reality_check=False)) is False
    print("  [OK]")


def test_promotable_only_demoted_and_needs_review():
    print("[TEST] promotable() is true only for DEMOTED/NEEDS_REVIEW...")
    assert PROMOTABLE_FROM == {GateStatus.DEMOTED, GateStatus.NEEDS_REVIEW}
    assert promotable(GateStatus.DEMOTED) is True
    assert promotable(GateStatus.NEEDS_REVIEW) is True
    assert promotable(GateStatus.REFUTED) is False
    assert promotable(GateStatus.CONFIRMED) is False
    assert promotable(GateStatus.UNREVIEWED) is False
    print("  [OK]")
