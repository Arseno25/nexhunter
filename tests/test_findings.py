"""Finding normalization, deduplication, and export."""

import json
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.findings.export import export, to_html, to_jsonl, to_markdown, to_sarif
from nexhunter.findings.models import (
    Category,
    Confidence,
    Finding,
    Severity,
    normalize_severity,
    severity_from_cvss,
)
from nexhunter.findings.store import FindingStore


def _finding(**overrides) -> Finding:
    payload = {
        "tool": "nuclei",
        "target": "example.com",
        "title": "Exposed admin panel",
        "category": Category.VULNERABILITY.value,
        "severity": "high",
    }
    payload.update(overrides)
    return Finding(**payload)


# --------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------


def test_severity_normalization():
    """Tool-specific severity spellings map onto one scale."""
    print("[TEST] Severity normalization...")

    assert normalize_severity("CRITICAL") is Severity.CRITICAL
    assert normalize_severity("Blocker") is Severity.CRITICAL
    assert normalize_severity("error") is Severity.HIGH
    assert normalize_severity("moderate") is Severity.MEDIUM
    assert normalize_severity("warning") is Severity.MEDIUM
    assert normalize_severity("minor") is Severity.LOW
    assert normalize_severity("informational") is Severity.INFO

    # A numeric CVSS score maps through the qualitative rating.
    assert normalize_severity("9.8") is Severity.CRITICAL
    assert normalize_severity("5.0") is Severity.MEDIUM

    print("  [OK] Severity spellings normalized")


def test_unknown_severity_does_not_inflate():
    """An unrecognized severity becomes INFO, never something worse.

    Guessing upward would make a report louder without making it more true.
    """
    print("[TEST] Unknown severity does not inflate...")

    assert normalize_severity("catastrophic-ultra") is Severity.INFO
    assert normalize_severity(None) is Severity.INFO
    assert normalize_severity("") is Severity.INFO

    print("  [OK] Unknown severities default to info")


def test_cvss_thresholds():
    """CVSS scores map to the standard qualitative bands."""
    print("[TEST] CVSS thresholds...")
    assert severity_from_cvss(9.8) is Severity.CRITICAL
    assert severity_from_cvss(7.0) is Severity.HIGH
    assert severity_from_cvss(6.9) is Severity.MEDIUM
    assert severity_from_cvss(3.9) is Severity.LOW
    assert severity_from_cvss(0.0) is Severity.INFO
    print("  [OK] CVSS bands correct")


def test_invalid_identifiers_dropped():
    """Malformed CVE and CWE ids are dropped, not passed to the reader.

    A reader trusts an identifier on sight; passing along a fabricated one is
    worse than omitting it.
    """
    print("[TEST] Invalid identifiers dropped...")
    finding = _finding(
        cve_ids=["CVE-2024-1234", "CVE-BOGUS", "not-a-cve", "cve-2023-99999"],
        cwe_ids=["CWE-79", "CWE-", "nonsense"],
    )

    assert finding.cve_ids == ["CVE-2024-1234", "CVE-2023-99999"]
    assert finding.cwe_ids == ["CWE-79"]

    print("  [OK] Malformed identifiers dropped")


def test_out_of_range_cvss_dropped():
    """A CVSS score outside 0-10 is dropped rather than clamped."""
    print("[TEST] Out-of-range CVSS dropped...")
    assert _finding(cvss_score=11.0).cvss_score is None
    assert _finding(cvss_score=-1).cvss_score is None
    assert _finding(cvss_score="not a number").cvss_score is None
    assert _finding(cvss_score=7.5).cvss_score == 7.5
    print("  [OK] Invalid scores dropped")


def test_cvss_vector_drives_score_and_severity():
    """A vector is a verified assessment: it computes the score (overriding
    any bare number also passed) and raises severity to match, but never
    lowers a severity the caller already set higher."""
    print("[TEST] CVSS vector drives score and severity...")
    critical_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    finding = _finding(cvss_vector=critical_vector, cvss_score=1.0)
    assert finding.cvss_score == 9.8, "vector overrides a bare cvss_score"
    assert finding.severity is Severity.CRITICAL

    low_vector = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
    stays_high = _finding(severity="critical", cvss_vector=low_vector)
    assert stays_high.severity is Severity.CRITICAL, "vector must not downgrade an explicit severity"
    assert stays_high.cvss_score == 1.8

    print("  [OK] Vector drives score, raises but never lowers severity")


def test_malformed_cvss_vector_dropped():
    """A malformed vector is dropped, not fatal -- same restraint as a
    malformed cve_id/cwe_id."""
    print("[TEST] Malformed CVSS vector dropped...")
    finding = _finding(cvss_vector="not a vector")
    assert finding.cvss_vector is None
    assert finding.cvss_score is None
    print("  [OK] Malformed vector dropped, not fatal")


def test_gate_status_defaults_unreviewed_and_round_trips():
    """gate_status/gate_notes default to unreviewed and survive to_dict/from_dict."""
    print("[TEST] Gate status default and round-trip...")
    finding = _finding()
    assert finding.gate_status == "unreviewed"
    assert finding.gate_notes == {}

    finding.gate_status = "confirmed"
    finding.gate_notes = {"impact": "verified in a scoped test account"}
    restored = Finding.from_dict(json.loads(json.dumps(finding.to_dict())))
    assert restored.gate_status == "confirmed"
    assert restored.gate_notes == {"impact": "verified in a scoped test account"}
    print("  [OK] Gate state round-trips through to_dict/from_dict")


def test_merge_preserves_gate_verdict_from_repeat_sighting():
    """A gated finding seen again (fresh Finding, so it starts unreviewed)
    must keep its verdict -- a repeat tool sighting is not a re-review."""
    print("[TEST] Merge preserves an existing gate verdict...")
    store = FindingStore()
    gated = store.add(_finding())
    gated.gate_status = "confirmed"
    gated.gate_notes = {"impact": "confirmed"}

    stored = store.add(_finding())  # same identity -> merges into `gated`
    assert stored.gate_status == "confirmed"
    assert stored.gate_notes == {"impact": "confirmed"}
    print("  [OK] Gate verdict survives a repeat sighting")


def test_review_confidence_out_of_range_dropped():
    """Same restraint as cvss_score: an invalid value is dropped, not clamped."""
    print("[TEST] Out-of-range review_confidence dropped...")
    assert _finding(review_confidence=150).review_confidence is None
    assert _finding(review_confidence=-1).review_confidence is None
    assert _finding(review_confidence="not a number").review_confidence is None
    assert _finding(review_confidence=72).review_confidence == 72
    print("  [OK] Invalid confidence dropped")


def test_review_confidence_round_trips():
    print("[TEST] review_confidence survives to_dict/from_dict...")
    finding = _finding(review_confidence=65)
    restored = Finding.from_dict(json.loads(json.dumps(finding.to_dict())))
    assert restored.review_confidence == 65
    print("  [OK] review_confidence round-trips")


def test_merge_preserves_review_confidence_alongside_gate_state():
    """review_confidence travels with gate_status/gate_notes on merge -- it
    was set as part of the same review, so it can't be adopted separately."""
    print("[TEST] Merge preserves review_confidence with the gate verdict...")
    store = FindingStore()
    gated = store.add(_finding())
    gated.gate_status = "demoted"
    gated.review_confidence = 55

    stored = store.add(_finding())
    assert stored.gate_status == "demoted"
    assert stored.review_confidence == 55
    print("  [OK] review_confidence survives a repeat sighting")


def test_disposition_property_reflects_gate_status_and_confidence():
    print("[TEST] Finding.disposition folds gate_status and review_confidence...")
    finding = _finding()
    assert finding.disposition == "unreviewed"
    finding.gate_status = "confirmed"
    assert finding.disposition == "confirmed"
    finding.review_confidence = 40
    assert finding.disposition == "lead"
    print("  [OK] disposition computed, not stored")


def test_canonical_narrative_fields_default_empty_and_round_trip():
    print("[TEST] root_cause/attack_flow/attack_chain_narrative default empty, round-trip...")
    finding = _finding()
    assert finding.root_cause == ""
    assert finding.attack_flow == []
    assert finding.attack_chain_narrative == []

    finding.root_cause = "missing ownership check in get_object_or_404"
    finding.attack_flow = ["authenticate as low-priv user", "request another user's resource"]
    finding.attack_chain_narrative = ["enumerate IDs", "exfiltrate every record in range"]
    restored = Finding.from_dict(json.loads(json.dumps(finding.to_dict())))
    assert restored.root_cause == finding.root_cause
    assert restored.attack_flow == finding.attack_flow
    assert restored.attack_chain_narrative == finding.attack_chain_narrative
    print("  [OK] narrative fields round-trip")


def test_presubmission_checklist_round_trips():
    print("[TEST] presubmission_checklist/notes round-trip...")
    finding = _finding()
    finding.presubmission_checklist = {"reality_check": True, "impact_validated": False}
    finding.presubmission_notes = {"impact_validated": "impact statement still too vague"}
    restored = Finding.from_dict(json.loads(json.dumps(finding.to_dict())))
    assert restored.presubmission_checklist == finding.presubmission_checklist
    assert restored.presubmission_notes == finding.presubmission_notes
    print("  [OK] presubmission state round-trips")


def test_promotion_fields_round_trip():
    print("[TEST] promoted_from/promotion_notes round-trip...")
    finding = _finding()
    finding.promoted_from = "demoted"
    finding.promotion_notes = "same root cause confirmed in finding abc123"
    restored = Finding.from_dict(json.loads(json.dumps(finding.to_dict())))
    assert restored.promoted_from == "demoted"
    assert restored.promotion_notes == "same root cause confirmed in finding abc123"
    print("  [OK] promotion audit trail round-trips")


def test_merge_preserves_narrative_and_presubmission_alongside_gate_state():
    """A repeat tool sighting must not wipe out review narrative or the
    pre-submission checklist any more than it wipes out the gate verdict."""
    print("[TEST] Merge preserves narrative and presubmission state...")
    store = FindingStore()
    gated = store.add(_finding())
    gated.gate_status = "confirmed"
    gated.root_cause = "missing ownership check"
    gated.attack_flow = ["step one"]
    gated.presubmission_checklist = {"reality_check": True}

    stored = store.add(_finding())
    assert stored.root_cause == "missing ownership check"
    assert stored.attack_flow == ["step one"]
    assert stored.presubmission_checklist == {"reality_check": True}
    print("  [OK] narrative and presubmission state survive a repeat sighting")


def test_merge_never_touches_promotion_audit_trail():
    """A promotion is a terminal, deliberate act -- a repeat tool sighting
    must never adopt, clear, or overwrite it."""
    print("[TEST] Merge never touches promoted_from/promotion_notes...")
    store = FindingStore()
    promoted = store.add(_finding())
    promoted.gate_status = "confirmed"
    promoted.promoted_from = "demoted"
    promoted.promotion_notes = "confirmed elsewhere"

    stored = store.add(_finding())
    assert stored.promoted_from == "demoted"
    assert stored.promotion_notes == "confirmed elsewhere"
    print("  [OK] promotion audit trail untouched by merge")


def test_observation_is_not_a_vulnerability():
    """Observations and vulnerabilities are distinct claims."""
    print("[TEST] Observation vs vulnerability...")

    observation = _finding(category=Category.OBSERVATION.value, title="Port 22 open")
    vulnerability = _finding(category=Category.VULNERABILITY.value)

    assert not observation.is_vulnerability, "an open port is a fact, not a weakness"
    assert vulnerability.is_vulnerability

    print("  [OK] Categories distinguished")


def test_parser_failure_is_recorded_not_swallowed():
    """A parser failure is a record, so it cannot look like a clean result."""
    print("[TEST] Parser failure recorded...")
    finding = Finding.parser_failure("nmap", "example.com", "malformed XML at line 3")

    assert finding.category == Category.PARSER_FAILURE.value
    assert not finding.is_vulnerability
    assert "malformed XML" in finding.description
    assert finding.confidence is Confidence.CONFIRMED

    print("  [OK] Parser failure kept as a distinct record")


# --------------------------------------------------------------------------
# Fingerprints and deduplication
# --------------------------------------------------------------------------


def test_fingerprint_is_stable_and_sha256():
    """The same finding produces the same SHA-256 fingerprint every time."""
    print("[TEST] Fingerprint stability...")
    first = _finding()
    second = _finding()

    assert first.fingerprint == second.fingerprint
    assert len(first.fingerprint) == 64, "expected a SHA-256 hex digest"
    int(first.fingerprint, 16)  # raises if not hex

    print("  [OK] Fingerprints stable")


def test_fingerprint_ignores_run_specific_fields():
    """A rerun does not create a new fingerprint."""
    print("[TEST] Fingerprint ignores run-specific fields...")
    original = _finding(execution_id="exec-1")
    rerun = _finding(
        execution_id="exec-2",
        first_seen_at=datetime.now(timezone.utc) + timedelta(days=1),
        severity="critical",
    )

    assert original.fingerprint == rerun.fingerprint, "execution id, timestamps, and severity must not change identity"

    print("  [OK] Reruns keep the same identity")


def test_fingerprint_distinguishes_real_differences():
    """Different target, title, or location means a different finding."""
    print("[TEST] Fingerprint distinguishes real differences...")
    base = _finding()

    assert base.fingerprint != _finding(target="other.com").fingerprint
    assert base.fingerprint != _finding(title="Something else").fingerprint
    assert base.fingerprint != _finding(location="/admin").fingerprint
    assert base.fingerprint != _finding(tool="nmap").fingerprint

    print("  [OK] Distinct findings stay distinct")


def test_deduplication_merges_repeats():
    """Storing the same finding twice keeps one record."""
    print("[TEST] Deduplication...")
    store = FindingStore()

    store.add(_finding())
    stored = store.add(_finding(severity="critical", cve_ids=["CVE-2024-1111"]))

    assert len(store) == 1, "a repeat sighting must not create a second record"
    assert stored.severity is Severity.CRITICAL, "the higher severity should win"
    assert "CVE-2024-1111" in stored.cve_ids, "new identifiers should be folded in"

    print("  [OK] Repeats merged, not duplicated")


def test_merge_does_not_downgrade_severity():
    """A later, milder sighting does not lower a finding's severity."""
    print("[TEST] Merge does not downgrade...")
    store = FindingStore()
    store.add(_finding(severity="critical"))
    stored = store.add(_finding(severity="low"))

    assert stored.severity is Severity.CRITICAL

    print("  [OK] Severity never downgraded by a merge")


def test_merge_recomputes_generated_remediation():
    """Merging a CWE that maps to a fix updates generated remediation, both
    directions; tool-supplied text is never touched."""
    print("[TEST] Merge recomputes generated remediation...")

    # Self carries no remediation or CWE; other adds CWE-89 (parameterized queries).
    base = _finding(category=Category.VULNERABILITY.value)
    base.merge(_finding(cwe_ids=["CWE-89"]))
    assert base.remediation and "parameterized" in base.remediation.lower()

    # Reverse order: self already carries CWE-89 and generated remediation.
    base = _finding(cwe_ids=["CWE-89"])
    base.merge(_finding())
    assert base.remediation and "parameterized" in base.remediation.lower()

    # Tool-supplied remediation survives a CWE-89 merge unchanged.
    custom = _finding(cwe_ids=["CWE-79"], remediation="custom fix")
    custom.merge(_finding(cwe_ids=["CWE-89"]))
    assert custom.remediation == "custom fix"

    print("  [OK] Generated remediation recomputed, tool text preserved")


def test_evidence_is_redacted():
    """Credentials in evidence are masked before storage.

    Evidence comes from the target, which controls it, and routinely contains
    credentials picked up mid-scan.
    """
    print("[TEST] Evidence redacted...")
    store = FindingStore()
    stored = store.add(
        _finding(
            category=Category.SECRET.value,
            evidence={"matched": "password=hunter2", "api_key": "AKIAIOSFODNN7EXAMPLE"},
        )
    )

    serialized = json.dumps(stored.evidence)
    assert "hunter2" not in serialized, f"credential survived into evidence: {serialized}"
    assert "AKIAIOSFODNN7EXAMPLE" not in serialized

    print("  [OK] Evidence redacted")


def test_store_is_concurrency_safe():
    """Parallel tool executions can write findings safely."""
    print("[TEST] Store concurrent writes...")
    store = FindingStore()
    errors = []

    def worker(index: int):
        try:
            for n in range(25):
                store.add(_finding(title=f"Finding {index}-{n}"))
                store.list()
        except Exception as exc:  # noqa: BLE001 - surfaced via errors
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors, f"concurrent writes raised: {errors[:3]}"
    assert len(store) == 200, f"expected 200 distinct findings, got {len(store)}"

    print("  [OK] 8 threads x 25 findings with no loss")


def test_store_summary():
    """The summary separates vulnerabilities, observations, and failures."""
    print("[TEST] Store summary...")
    store = FindingStore()
    store.add(_finding(title="Vuln A", severity="critical"))
    store.add(_finding(title="Obs A", category=Category.OBSERVATION.value, severity="info"))
    store.add(Finding.parser_failure("nmap", "example.com", "bad XML"))

    summary = store.summary()
    assert summary["total"] == 3
    assert summary["vulnerabilities"] == 1
    assert summary["observations"] == 1
    assert summary["parser_failures"] == 1
    assert summary["by_severity"]["critical"] == 1

    print("  [OK] Summary separates record kinds")


def test_store_bounded():
    """The store does not grow without limit, and sheds the least severe."""
    print("[TEST] Store bounded...")
    store = FindingStore(max_findings=10)

    store.add(_finding(title="Keep me", severity="critical"))
    for n in range(30):
        store.add(_finding(title=f"Noise {n}", severity="info"))

    assert len(store) <= 10, f"store grew unbounded: {len(store)}"
    titles = [f.title for f in store.list()]
    assert "Keep me" in titles, "the critical finding should outlive the noise"

    print("  [OK] Bounded, keeping the most severe")


# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------


def test_json_and_jsonl_export():
    """JSON and JSONL round-trip."""
    print("[TEST] JSON and JSONL export...")
    findings = [_finding(title="A"), _finding(title="B")]

    parsed = json.loads(export(findings, "json"))
    assert len(parsed) == 2
    assert parsed[0]["fingerprint"]

    lines = to_jsonl(findings).splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["title"] == "A"

    print("  [OK] JSON and JSONL valid")


def test_markdown_separates_findings_from_observations():
    """The report does not mix facts in with findings."""
    print("[TEST] Markdown export...")
    findings = [
        _finding(title="SQL injection", severity="critical", description="Injectable parameter"),
        _finding(title="Port 22 open", category=Category.OBSERVATION.value),
        Finding.parser_failure("nmap", "example.com", "malformed output"),
    ]
    report = to_markdown(findings)

    assert "## Summary" in report
    assert "## Findings" in report
    assert "## Observations" in report
    assert "## Parser failures" in report
    assert "SQL injection" in report
    assert "not** clean results" in report, "parser failures must be flagged as unknown, not clean"

    print("  [OK] Sections separated")


def test_html_escapes_untrusted_content():
    """Findings carry target-controlled text, so HTML output is escaped."""
    print("[TEST] HTML escaping...")
    findings = [
        _finding(
            title="<script>alert('xss')</script>",
            target="<img src=x onerror=alert(1)>",
        )
    ]
    report = to_html(findings)

    # What matters is that no tag delimiter survives unescaped. The payload's
    # text may still appear -- as inert text, which is the point of escaping.
    assert "<script>alert" not in report, "unescaped script tag in report"
    assert "<img src=x" not in report, "unescaped img tag in report"
    assert "&lt;script&gt;" in report, "the payload should appear escaped"
    assert "&lt;img src=x onerror=alert(1)&gt;" in report

    print("  [OK] Untrusted content escaped")


def test_sarif_is_valid_and_complete():
    """SARIF output has the required structure."""
    print("[TEST] SARIF export...")
    findings = [
        _finding(
            title="Hardcoded secret",
            category=Category.SECRET.value,
            severity="critical",
            location="src/config.py",
            cwe_ids=["CWE-798"],
        ),
        _finding(title="Open port", category=Category.OBSERVATION.value, severity="info"),
    ]
    document = json.loads(to_sarif(findings))

    assert document["version"] == "2.1.0"
    assert "$schema" in document
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "NexHunter"
    assert len(run["tool"]["driver"]["rules"]) == 2
    assert len(run["results"]) == 2

    for result in run["results"]:
        assert result["level"] in {"error", "warning", "note", "none"}
        assert result["ruleId"]
        assert result["message"]["text"]
        assert result["fingerprints"]["nexhunter/v1"]
        assert result["locations"], "every result needs a location"

    print("  [OK] SARIF structurally valid")


def test_sarif_does_not_invent_file_paths():
    """A network finding is a logical location, not a fabricated file path."""
    print("[TEST] SARIF does not invent paths...")
    findings = [_finding(title="Open port", target="example.com", location="443")]
    run = json.loads(to_sarif(findings))["runs"][0]

    location = run["results"][0]["locations"][0]
    assert "physicalLocation" not in location, "a host and port is not a file; SARIF must not claim it is"
    assert location["logicalLocations"][0]["name"] == "443"

    print("  [OK] No fabricated file paths")


def test_attack_mapping_from_cwe():
    """CWEs map onto MITRE ATT&CK techniques, deterministically."""
    print("[TEST] ATT&CK mapping from CWE...")

    assert _finding(cwe_ids=["CWE-89"]).attack_ids == ["T1190"]
    assert _finding(cwe_ids=["CWE-79"]).attack_ids == ["T1059.007"]
    assert _finding(cwe_ids=["CWE-918"]).attack_ids == ["T1090"]

    # Multiple CWEs fold in, deduplicated and sorted; unknown CWEs add nothing.
    assert _finding(cwe_ids=["CWE-89", "CWE-918", "CWE-9999"]).attack_ids == ["T1090", "T1190"]

    # Explicitly set ids are kept; malformed ones are dropped.
    assert _finding(cwe_ids=["CWE-89"], attack_ids=["T1078"]).attack_ids == ["T1078"]
    assert _finding(attack_ids=["T12", "nonsense"]).attack_ids == []

    print("  [OK] ATT&CK techniques derived from CWEs")


def test_remediation_autofill():
    """A concrete remediation is filled in when the tool provided none."""
    print("[TEST] Remediation autofill...")

    sqli = _finding(cwe_ids=["CWE-89"])
    assert sqli.remediation and "parameterized" in sqli.remediation.lower()

    secret = _finding(category=Category.SECRET.value)
    assert secret.remediation and "rotate" in secret.remediation

    # A remediation the tool provided is never overwritten.
    custom = _finding(cwe_ids=["CWE-89"], remediation="custom fix")
    assert custom.remediation == "custom fix"

    # Observations are facts, not weaknesses; they get no invented fix.
    observation = _finding(category=Category.OBSERVATION.value)
    assert observation.remediation is None

    print("  [OK] Remediation knowledge base applied")


def test_artifacts_rendered_in_reports():
    """Evidence files (screenshots, pcaps) surface in every report format."""
    print("[TEST] Artifacts rendered...")
    finding = _finding(
        cwe_ids=["CWE-89"],
        artifacts=["screenshots/xss-proof.png", "captures/traffic.pcap"],
    )

    markdown = to_markdown([finding])
    assert "**Evidence artifacts**" in markdown
    assert "`screenshots/xss-proof.png`" in markdown
    assert "MITRE ATT&CK" in markdown
    assert "T1190 (Exploit Public-Facing Application)" in markdown

    html_report = to_html([finding])
    assert "screenshots/xss-proof.png" in html_report
    assert "T1190" in html_report

    sarif = json.loads(to_sarif([finding]))
    result = sarif["runs"][0]["results"][0]
    assert result["properties"]["attack_ids"] == ["T1190"]
    assert result["properties"]["artifacts"] == ["screenshots/xss-proof.png", "captures/traffic.pcap"]

    serialized = finding.to_dict()
    assert serialized["attack_ids"] == ["T1190"]
    assert serialized["artifacts"] == ["screenshots/xss-proof.png", "captures/traffic.pcap"]

    print("  [OK] Artifacts and ATT&CK rendered everywhere")


def test_unknown_export_format_rejected():
    """An unknown format is an error, not a silent default."""
    print("[TEST] Unknown export format rejected...")
    try:
        export([_finding()], "pdf")
        raise AssertionError("expected an unknown format to raise")
    except ValueError as exc:
        assert "unknown format" in str(exc)
    print("  [OK] Unknown format rejected")


def test_empty_export_is_valid():
    """Exporting nothing produces valid output in every format."""
    print("[TEST] Empty export...")
    assert json.loads(export([], "json")) == []
    assert to_jsonl([]) == ""
    assert "No findings recorded" in to_markdown([])
    assert "No findings recorded" in to_html([])
    assert json.loads(to_sarif([]))["runs"][0]["results"] == []
    print("  [OK] Empty exports valid")


def test_add_many_persists_once(tmp_path):
    """Bulk insert writes the findings file a single time, not per finding.

    Fails if add_many rewrites the whole file once per finding (O(n) I/O).
    """
    print("[TEST] add_many persists once...")
    store = FindingStore(path=tmp_path / "findings.json")
    persists = []
    real_persist = store._persist
    store._persist = lambda: (persists.append(1), real_persist())[1]

    store.add_many([_finding(title=f"Finding {i}") for i in range(3)])

    assert len(persists) == 1, f"expected one persist, got {len(persists)}"
    assert len(store) == 3
    print("  [OK] Single persist for a bulk insert")


if __name__ == "__main__":
    print("\n=== Finding Tests ===\n")
    test_severity_normalization()
    test_unknown_severity_does_not_inflate()
    test_cvss_thresholds()
    test_invalid_identifiers_dropped()
    test_out_of_range_cvss_dropped()
    test_cvss_vector_drives_score_and_severity()
    test_malformed_cvss_vector_dropped()
    test_gate_status_defaults_unreviewed_and_round_trips()
    test_merge_preserves_gate_verdict_from_repeat_sighting()
    test_review_confidence_out_of_range_dropped()
    test_review_confidence_round_trips()
    test_merge_preserves_review_confidence_alongside_gate_state()
    test_disposition_property_reflects_gate_status_and_confidence()
    test_canonical_narrative_fields_default_empty_and_round_trip()
    test_presubmission_checklist_round_trips()
    test_promotion_fields_round_trip()
    test_merge_preserves_narrative_and_presubmission_alongside_gate_state()
    test_merge_never_touches_promotion_audit_trail()
    test_observation_is_not_a_vulnerability()
    test_parser_failure_is_recorded_not_swallowed()
    test_fingerprint_is_stable_and_sha256()
    test_fingerprint_ignores_run_specific_fields()
    test_fingerprint_distinguishes_real_differences()
    test_deduplication_merges_repeats()
    test_merge_does_not_downgrade_severity()
    test_merge_recomputes_generated_remediation()
    test_evidence_is_redacted()
    test_store_is_concurrency_safe()
    test_store_summary()
    test_store_bounded()
    test_json_and_jsonl_export()
    test_markdown_separates_findings_from_observations()
    test_html_escapes_untrusted_content()
    test_sarif_is_valid_and_complete()
    test_sarif_does_not_invent_file_paths()
    test_attack_mapping_from_cwe()
    test_remediation_autofill()
    test_artifacts_rendered_in_reports()
    test_unknown_export_format_rejected()
    test_empty_export_is_valid()
    print("\n=== All Finding Tests Passed ===\n")
