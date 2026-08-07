"""Batch triage: bucket findings by disposition (findings/triage.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.findings.models import Category, Finding
from nexhunter.findings.triage import BUCKET_ORDER, buckets


def _finding(severity="medium", **overrides) -> Finding:
    payload = {"tool": "nuclei", "target": "x.example", "title": "t", "category": Category.VULNERABILITY.value, "severity": severity}
    payload.update(overrides)
    return Finding(**payload)


def test_all_buckets_always_present():
    print("[TEST] every disposition bucket is present even when empty...")
    result = buckets([])
    assert set(result) == set(BUCKET_ORDER)
    assert all(v == [] for v in result.values())
    print("  [OK]")


def test_buckets_by_disposition():
    print("[TEST] findings land in the bucket matching their disposition...")
    confirmed = _finding()
    confirmed.gate_status = "confirmed"
    refuted = _finding()
    refuted.gate_status = "refuted"
    unreviewed = _finding()

    result = buckets([confirmed, refuted, unreviewed])
    assert result["confirmed"] == [confirmed]
    assert result["refuted"] == [refuted]
    assert result["unreviewed"] == [unreviewed]
    print("  [OK]")


def test_low_confidence_confirmed_lands_in_lead_bucket():
    print("[TEST] confirmed-but-low-confidence findings land in 'lead', not 'confirmed'...")
    f = _finding()
    f.gate_status = "confirmed"
    f.review_confidence = 40
    result = buckets([f])
    assert result["lead"] == [f]
    assert result["confirmed"] == []
    print("  [OK]")


def test_each_bucket_sorted_most_severe_first():
    print("[TEST] within a bucket, findings sort most severe first...")
    low = _finding(severity="low", title="low one")
    critical = _finding(severity="critical", title="critical one")
    medium = _finding(severity="medium", title="medium one")
    for f in (low, critical, medium):
        f.gate_status = "confirmed"
    result = buckets([low, critical, medium])
    assert [f.severity.value for f in result["confirmed"]] == ["critical", "medium", "low"]
    print("  [OK]")
