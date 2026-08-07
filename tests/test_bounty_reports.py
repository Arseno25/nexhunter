"""Per-platform bug bounty report templates."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest

from nexhunter.findings import bounty_reports as br
from nexhunter.findings.models import Category, Finding


def _finding(**overrides) -> Finding:
    payload = {
        "tool": "nuclei",
        "target": "https://api.target.com/users/1",
        "title": "IDOR on user profile endpoint",
        "category": Category.VULNERABILITY.value,
        "description": "The /users/{id} endpoint does not verify ownership.",
        "cwe_ids": ["CWE-639"],
        "remediation": "Verify the authenticated user owns the requested resource.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    }
    payload.update(overrides)
    return Finding(**payload)


@pytest.mark.parametrize("platform", sorted(set(br.PLATFORMS)))
def test_every_platform_renders_without_error(platform):
    print(f"[TEST] {platform} renders a non-empty report...")
    finding = _finding()
    finding.gate_status = "confirmed"
    finding.gate_notes = {"impact": "any user can read any other user's PII"}
    report = br.render(finding, platform)
    assert finding.title in report
    assert "IDOR" in report
    print("  [OK]")


def test_unreviewed_finding_gets_warning_banner():
    print("[TEST] unreviewed finding surfaces a warning, not silence...")
    report = br.render(_finding(), "hackerone")
    assert "Not yet reviewed" in report
    print("  [OK]")


def test_demoted_finding_gets_caveat_banner():
    print("[TEST] demoted finding surfaces the caveat, not silence...")
    finding = _finding()
    finding.gate_status = "demoted"
    report = br.render(finding, "hackerone")
    assert "Demoted" in report
    print("  [OK]")


def test_refuted_finding_gets_warning_banner():
    print("[TEST] refuted finding surfaces a warning too...")
    finding = _finding()
    finding.gate_status = "refuted"
    report = br.render(finding, "hackerone")
    assert "Refuted" in report
    print("  [OK]")


def test_confirmed_finding_has_no_warning_banner():
    print("[TEST] confirmed finding has no gate warning...")
    finding = _finding()
    finding.gate_status = "confirmed"
    report = br.render(finding, "hackerone")
    assert "Not yet reviewed" not in report
    assert "Refuted" not in report
    assert "Needs review" not in report
    print("  [OK]")


def test_impact_comes_from_gate_notes_not_fabricated():
    """Impact must be the reviewer's own words (gate_notes['impact']), never
    invented from evidence that says nothing about impact."""
    print("[TEST] impact section sources gate_notes, not guessed...")
    finding = _finding(evidence={"request": "GET /users/2", "response_status": 200})
    finding.gate_notes = {"impact": "confirmed cross-account PII read in a scoped test"}
    report = br.render(finding, "generic")
    assert "confirmed cross-account PII read in a scoped test" in report

    finding_no_gate_notes = _finding(evidence={"request": "GET /users/2", "response_status": 200})
    report_no_impact = br.render(finding_no_gate_notes, "generic")
    assert "## Impact" not in report_no_impact, "empty impact section must be omitted, not fabricated"
    print("  [OK]")


def test_steps_to_reproduce_uses_real_evidence():
    print("[TEST] steps-to-reproduce renders the finding's actual evidence...")
    finding = _finding(evidence={"request": "GET /users/2 Authorization: Bearer x"})
    report = br.render(finding, "hackerone")
    assert "GET /users/2 Authorization: Bearer x" in report
    print("  [OK]")


def test_bugcrowd_priority_mapping():
    print("[TEST] Bugcrowd priority maps deterministically from severity...")
    for severity, expected_priority in (
        ("critical", "P1"), ("high", "P2"), ("medium", "P3"), ("low", "P4"), ("info", "P5"),
    ):
        # cvss_vector=None: the fixture's default vector implies "medium",
        # which would floor a lower requested severity via the
        # never-downgrade rule -- irrelevant to what this test checks.
        report = br.render(_finding(severity=severity, cvss_vector=None), "bugcrowd")
        assert f"**Priority:** {expected_priority}" in report
    print("  [OK]")


def test_immunefi_does_not_fabricate_impact_category():
    """Immunefi's severity taxonomy is impact-category (fund loss/downtime),
    not CVSS -- the template must say so, never assert a false equivalence."""
    print("[TEST] Immunefi template refuses to invent an Impact Category...")
    report = br.render(_finding(), "immunefi")
    assert "not auto-assigned" in report
    assert "NexHunter severity" in report
    print("  [OK]")


def test_hackerone_and_h1_are_the_same_template():
    print("[TEST] 'h1' is an alias for 'hackerone'...")
    finding = _finding()
    assert br.render(finding, "h1") == br.render(finding, "hackerone")
    print("  [OK]")


def test_unknown_platform_rejected():
    print("[TEST] unknown platform name raises ValueError...")
    with pytest.raises(ValueError, match="unknown platform"):
        br.render(_finding(), "notaplatform")
    print("  [OK]")


def test_lead_depth_withholds_poc_and_remediation():
    print("[TEST] review_confidence < 60 withholds PoC and remediation...")
    finding = _finding(evidence={"request": "GET /users/2"})
    finding.review_confidence = 40
    report = br.render(finding, "generic")
    assert "Lead only" in report
    assert "GET /users/2" not in report
    assert "Verify the authenticated user owns" not in report
    print("  [OK]")


def test_partial_depth_keeps_poc_withholds_remediation():
    print("[TEST] review_confidence 60-79 keeps PoC, withholds remediation...")
    finding = _finding(evidence={"request": "GET /users/2"})
    finding.review_confidence = 70
    report = br.render(finding, "generic")
    assert "Partial confidence" in report
    assert "GET /users/2" in report
    assert "Verify the authenticated user owns" not in report
    print("  [OK]")


def test_full_depth_at_or_above_eighty():
    print("[TEST] review_confidence >= 80 renders everything, no depth banner...")
    finding = _finding(evidence={"request": "GET /users/2"})
    finding.review_confidence = 80
    report = br.render(finding, "generic")
    assert "Lead only" not in report
    assert "Partial confidence" not in report
    assert "GET /users/2" in report
    assert "Verify the authenticated user owns" in report
    print("  [OK]")


def test_never_scored_defaults_to_full():
    print("[TEST] a finding never scored for confidence renders in full...")
    finding = _finding(evidence={"request": "GET /users/2"})
    assert finding.review_confidence is None
    report = br.render(finding, "generic")
    assert "Lead only" not in report
    assert "Partial confidence" not in report
    assert "GET /users/2" in report
    print("  [OK]")


def test_case_insensitive_platform_name():
    print("[TEST] platform name is case-insensitive...")
    finding = _finding()
    assert br.render(finding, "HackerOne") == br.render(finding, "hackerone")
    print("  [OK]")


def test_root_cause_and_attack_flow_render_only_when_supplied():
    print("[TEST] Root Cause / Attack Flow sections omitted when empty, present when set...")
    bare = _finding()
    report_bare = br.render(bare, "generic")
    assert "## Root Cause" not in report_bare
    assert "## Attack Flow" not in report_bare

    filled = _finding()
    filled.root_cause = "get_object_or_404 used with no ownership check"
    filled.attack_flow = ["authenticate as low-priv user", "request another user's resource by id"]
    report_filled = br.render(filled, "generic")
    assert "## Root Cause" in report_filled
    assert "get_object_or_404 used with no ownership check" in report_filled
    assert "## Attack Flow" in report_filled
    assert "1. authenticate as low-priv user" in report_filled
    assert "2. request another user's resource by id" in report_filled
    print("  [OK]")


def test_realistic_attack_chain_renders_only_when_supplied():
    print("[TEST] Realistic Attack Chain section omitted when empty, present when set...")
    bare = _finding()
    assert "## Realistic Attack Chain" not in br.render(bare, "generic")

    filled = _finding()
    filled.attack_chain_narrative = ["enumerate booking IDs", "exfiltrate PII for every booking in range"]
    report = br.render(filled, "generic")
    assert "## Realistic Attack Chain" in report
    assert "1. enumerate booking IDs" in report
    assert "2. exfiltrate PII for every booking in range" in report
    print("  [OK]")


def test_immunefi_asset_type_and_tech_stack_from_evidence_only():
    print("[TEST] Immunefi Asset Type/Tech Stack render only when evidence provides them...")
    bare = _finding()
    report_bare = br.render(bare, "immunefi")
    assert "**Asset Type:**" not in report_bare
    assert "**Blockchain/Tech Stack:**" not in report_bare

    filled = _finding(evidence={"asset_type": "Smart Contract", "tech_stack": "Solidity / EVM"})
    report_filled = br.render(filled, "immunefi")
    assert "**Asset Type:** Smart Contract" in report_filled
    assert "**Blockchain/Tech Stack:** Solidity / EVM" in report_filled
    print("  [OK]")


def test_dividers_appear_between_rendered_sections_only():
    print("[TEST] '---' divider precedes every rendered section, never an omitted one...")
    finding = _finding()
    finding.gate_status = "confirmed"
    finding.gate_notes = {"impact": "impact text"}
    report = br.render(finding, "hackerone")
    assert "---\n\n## Summary" in report
    assert "---\n\n## Impact" in report
    # Steps To Reproduce and Supporting Material are empty for this finding
    # (no evidence, no references/artifacts) -- must not leave a dangling
    # divider where they were omitted.
    assert "---\n\n## Steps To Reproduce" not in report
    assert "\n\n\n---\n\n---\n\n" not in report  # no back-to-back dividers
    print("  [OK]")


def test_narrative_sections_appear_in_every_platform_template():
    print("[TEST] Root Cause/Attack Flow/Attack Chain wired into every platform, not just generic...")
    finding = _finding()
    finding.root_cause = "root cause text"
    finding.attack_flow = ["flow step"]
    finding.attack_chain_narrative = ["chain step"]
    for platform in sorted(set(br.PLATFORMS)):
        report = br.render(finding, platform)
        assert "root cause text" in report, f"{platform} dropped Root Cause"
        assert "flow step" in report, f"{platform} dropped Attack Flow"
        assert "chain step" in report, f"{platform} dropped Realistic Attack Chain"
    print("  [OK]")
