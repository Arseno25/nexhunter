"""End-to-end tests for /api/findings/<id>, /api/findings/<id>/gates, and
/api/cvss/score -- the finding-detail lookup, the 4-gate validator, and the
CVSS scorer, exercised through the real Flask app."""

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest
from werkzeug.serving import make_server

from nexhunter.api import server
from nexhunter.findings.models import Category, Finding


@pytest.fixture(scope="module")
def base_url():
    httpd = make_server("127.0.0.1", 0, server.app, threaded=True)
    port = httpd.server_port
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _get(url):
    req = urllib.request.Request(url)  # noqa: S310 - base_url localhost test fixture
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _post(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_cvss_score_endpoint(base_url):
    print("[TEST] POST /api/cvss/score...")
    status, body = _post(f"{base_url}/api/cvss/score", {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    assert status == 200
    assert body["ok"] is True
    assert body["base_score"] == 9.8
    assert body["severity"] == "critical"
    print("  [OK]")


def test_cvss_score_endpoint_rejects_malformed(base_url):
    print("[TEST] POST /api/cvss/score rejects a malformed vector...")
    status, body = _post(f"{base_url}/api/cvss/score", {"vector": "not a vector"})
    assert status == 400
    assert body["ok"] is False
    assert body["code"] == "INVALID_VECTOR"
    print("  [OK]")


def test_finding_get_roundtrip(base_url):
    print("[TEST] GET /api/findings/<id> returns a stored finding...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="findings-api-test.example", title="Exposed panel", category=Category.VULNERABILITY.value)
    )
    status, body = _get(f"{base_url}/api/findings/{finding.id}")
    assert status == 200
    assert body["ok"] is True
    assert body["finding"]["id"] == finding.id
    assert body["finding"]["gate_status"] == "unreviewed"
    print("  [OK]")


def test_finding_get_missing_is_404(base_url):
    print("[TEST] GET /api/findings/<id> 404s on an unknown id...")
    status, body = _get(f"{base_url}/api/findings/does-not-exist")
    assert status == 404
    assert body["code"] == "NOT_FOUND"
    print("  [OK]")


def test_finding_gates_confirms_on_all_pass(base_url):
    print("[TEST] POST /api/findings/<id>/gates confirms when all 4 gates pass...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="gates-test.example", title="SQLi", category=Category.VULNERABILITY.value)
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {
            "refutation": "pass",
            "reachability": "pass",
            "trigger": "pass",
            "impact": "pass",
            "impact_notes": "confirmed data exfil in a scoped test account",
        },
    )
    assert status == 200
    assert body["finding"]["gate_status"] == "confirmed"
    assert body["finding"]["gate_notes"]["impact"] == "confirmed data exfil in a scoped test account"
    print("  [OK]")


def test_finding_gates_refutes_on_any_fail(base_url):
    print("[TEST] POST /api/findings/<id>/gates refutes on a single FAIL...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="gates-test-2.example", title="XSS", category=Category.VULNERABILITY.value)
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {
            "refutation": "pass",
            "reachability": "pass",
            "trigger": "fail",
            "impact": "pass",
            "trigger_notes": "requires an already-authenticated admin session, no way to reach it unauthenticated",
        },
    )
    assert status == 200
    assert body["finding"]["gate_status"] == "refuted"
    print("  [OK]")


def test_finding_gates_needs_review_on_unsure(base_url):
    print("[TEST] POST /api/findings/<id>/gates needs_review on UNSURE with no FAIL...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="gates-test-3.example", title="IDOR", category=Category.VULNERABILITY.value)
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {"refutation": "pass", "reachability": "unsure", "trigger": "pass", "impact": "pass"},
    )
    assert status == 200
    assert body["finding"]["gate_status"] == "needs_review"
    print("  [OK]")


def test_finding_gates_scores_confidence_when_flags_given(base_url):
    print("[TEST] POST /api/findings/<id>/gates computes review_confidence from flags...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="confidence-test.example", title="Blind SSRF", category=Category.VULNERABILITY.value)
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {
            "refutation": "pass", "reachability": "pass", "trigger": "pass", "impact": "pass",
            "partial_attack_path": True, "requires_user_interaction": True,
        },
    )
    assert status == 200
    assert body["finding"]["review_confidence"] == 100 - 20 - 10
    print("  [OK]")


def test_finding_gates_leaves_confidence_unscored_without_flags(base_url):
    print("[TEST] POST /api/findings/<id>/gates leaves review_confidence None with no flags given...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="confidence-test-2.example", title="XXE", category=Category.VULNERABILITY.value)
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {"refutation": "pass", "reachability": "pass", "trigger": "pass", "impact": "pass"},
    )
    assert status == 200
    assert body["finding"]["review_confidence"] is None
    print("  [OK]")


def test_finding_gates_demotes_on_demote_with_no_fail(base_url):
    print("[TEST] POST /api/findings/<id>/gates demotes on DEMOTE with no FAIL...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="gates-test-7.example", title="Role bypass", category=Category.VULNERABILITY.value)
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {
            "refutation": "pass",
            "reachability": "pass",
            "trigger": "demote",
            "impact": "pass",
            "trigger_notes": "only a trusted admin role can reach this path in normal operation",
        },
    )
    assert status == 200
    assert body["finding"]["gate_status"] == "demoted"
    print("  [OK]")


def test_finding_gates_rejects_observation_category(base_url):
    print("[TEST] POST /api/findings/<id>/gates refuses a non-vulnerability finding...")
    finding = server.FINDINGS.add(
        Finding(tool="nmap", target="gates-test-4.example", title="port 22 open", category=Category.OBSERVATION.value)
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {"refutation": "pass", "reachability": "pass", "trigger": "pass", "impact": "pass"},
    )
    assert status == 400
    assert body["code"] == "NOT_GATEABLE"
    print("  [OK]")


def test_finding_gates_rejects_bad_verdict(base_url):
    print("[TEST] POST /api/findings/<id>/gates rejects an invalid verdict value...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="gates-test-5.example", title="LFI", category=Category.VULNERABILITY.value)
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {"refutation": "maybe", "reachability": "pass", "trigger": "pass", "impact": "pass"},
    )
    assert status == 400
    assert body["code"] == "INVALID_PARAMS"
    print("  [OK]")


def test_finding_report_endpoint(base_url):
    print("[TEST] POST /api/findings/<id>/report renders a platform report...")
    finding = server.FINDINGS.add(
        Finding(
            tool="nuclei",
            target="report-test.example",
            title="Reflected XSS",
            category=Category.VULNERABILITY.value,
            description="Unescaped query param reflected into the page.",
        )
    )
    status, body = _post(f"{base_url}/api/findings/{finding.id}/report", {"platform": "hackerone"})
    assert status == 200
    assert body["ok"] is True
    assert body["platform"] == "hackerone"
    assert "Reflected XSS" in body["report"]
    print("  [OK]")


def test_finding_report_endpoint_defaults_to_generic(base_url):
    print("[TEST] POST /api/findings/<id>/report defaults to 'generic' platform...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="report-test-2.example", title="Open redirect", category=Category.VULNERABILITY.value)
    )
    status, body = _post(f"{base_url}/api/findings/{finding.id}/report", {})
    assert status == 200
    assert body["platform"] == "generic"
    print("  [OK]")


def test_finding_report_endpoint_rejects_bad_platform(base_url):
    print("[TEST] POST /api/findings/<id>/report rejects an unknown platform...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="report-test-3.example", title="SSRF", category=Category.VULNERABILITY.value)
    )
    status, body = _post(f"{base_url}/api/findings/{finding.id}/report", {"platform": "notaplatform"})
    assert status == 400
    assert body["code"] == "INVALID_PARAMS"
    print("  [OK]")


def test_finding_report_endpoint_missing_finding_404s(base_url):
    print("[TEST] POST /api/findings/<id>/report 404s on an unknown finding...")
    status, body = _post(f"{base_url}/api/findings/does-not-exist/report", {"platform": "hackerone"})
    assert status == 404
    print("  [OK]")


def test_finding_gates_applies_severity_adjustment(base_url):
    print("[TEST] POST /api/findings/<id>/gates lowers severity via adjustment flags...")
    finding = server.FINDINGS.add(
        Finding(
            tool="nuclei", target="severity-adj.example", title="Timing-dependent race",
            category=Category.VULNERABILITY.value, severity="critical",
        )
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {
            "refutation": "pass", "reachability": "pass", "trigger": "pass", "impact": "pass",
            "timing_dependent": True, "requires_large_capital": True,
        },
    )
    assert status == 200
    assert body["finding"]["severity"] == "medium"  # critical(4) - 2 flags = rank 2 = medium
    print("  [OK]")


def test_finding_gates_no_severity_flags_leaves_severity_unchanged(base_url):
    print("[TEST] POST /api/findings/<id>/gates leaves severity alone with no flags...")
    finding = server.FINDINGS.add(
        Finding(
            tool="nuclei", target="severity-adj-2.example", title="No adjustment",
            category=Category.VULNERABILITY.value, severity="high",
        )
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {"refutation": "pass", "reachability": "pass", "trigger": "pass", "impact": "pass"},
    )
    assert status == 200
    assert body["finding"]["severity"] == "high"
    print("  [OK]")


def test_finding_gates_captures_canonical_narrative(base_url):
    print("[TEST] POST /api/findings/<id>/gates captures root_cause/attack_flow/attack_chain_narrative...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="narrative.example", title="IDOR", category=Category.VULNERABILITY.value)
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {
            "refutation": "pass", "reachability": "pass", "trigger": "pass", "impact": "pass",
            "root_cause": "missing ownership check",
            "attack_flow": ["step one", "step two"],
            "attack_chain_narrative": ["chain step"],
        },
    )
    assert status == 200
    assert body["finding"]["root_cause"] == "missing ownership check"
    assert body["finding"]["attack_flow"] == ["step one", "step two"]
    assert body["finding"]["attack_chain_narrative"] == ["chain step"]
    print("  [OK]")


def test_presubmission_endpoint_reports_ready(base_url):
    print("[TEST] POST /api/findings/<id>/presubmission reports ready when all true...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="presub.example", title="XSS", category=Category.VULNERABILITY.value)
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/presubmission",
        {
            "reality_check": True, "impact_validated": True,
            "deduplication_checked": True, "report_quality_checked": True,
        },
    )
    assert status == 200
    assert body["ready"] is True
    assert body["finding"]["presubmission_checklist"]["reality_check"] is True
    print("  [OK]")


def test_presubmission_endpoint_reports_not_ready(base_url):
    print("[TEST] POST /api/findings/<id>/presubmission reports not ready when one item is false...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="presub-2.example", title="SQLi", category=Category.VULNERABILITY.value)
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/presubmission",
        {
            "reality_check": True, "impact_validated": True,
            "deduplication_checked": False, "report_quality_checked": True,
        },
    )
    assert status == 200
    assert body["ready"] is False
    print("  [OK]")


def test_presubmission_endpoint_rejects_missing_item(base_url):
    print("[TEST] POST /api/findings/<id>/presubmission rejects an incomplete checklist...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="presub-3.example", title="LFI", category=Category.VULNERABILITY.value)
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/presubmission",
        {"reality_check": True, "impact_validated": True},
    )
    assert status == 400
    assert body["code"] == "INVALID_PARAMS"
    print("  [OK]")


def test_presubmission_endpoint_missing_finding_404s(base_url):
    print("[TEST] POST /api/findings/<id>/presubmission 404s on an unknown finding...")
    status, body = _post(
        f"{base_url}/api/findings/does-not-exist/presubmission",
        {"reality_check": True, "impact_validated": True, "deduplication_checked": True, "report_quality_checked": True},
    )
    assert status == 404
    print("  [OK]")


def test_promote_finding_demoted_to_confirmed(base_url):
    print("[TEST] POST /api/findings/<id>/promote moves DEMOTED to CONFIRMED...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="promote.example", title="Role bypass", category=Category.VULNERABILITY.value)
    )
    _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {"refutation": "pass", "reachability": "pass", "trigger": "demote", "impact": "pass"},
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/promote",
        {"reason": "same root cause confirmed in a second, independent finding"},
    )
    assert status == 200
    assert body["finding"]["gate_status"] == "confirmed"
    assert body["finding"]["promoted_from"] == "demoted"
    assert "same root cause confirmed" in body["finding"]["promotion_notes"]
    print("  [OK]")


def test_promote_finding_rejects_confirmed(base_url):
    print("[TEST] POST /api/findings/<id>/promote refuses a finding that isn't DEMOTED/NEEDS_REVIEW...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="promote-2.example", title="Already confirmed", category=Category.VULNERABILITY.value)
    )
    _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {"refutation": "pass", "reachability": "pass", "trigger": "pass", "impact": "pass"},
    )
    status, body = _post(f"{base_url}/api/findings/{finding.id}/promote", {"reason": "trying anyway"})
    assert status == 400
    assert body["code"] == "NOT_PROMOTABLE"
    print("  [OK]")


def test_promote_finding_requires_reason(base_url):
    print("[TEST] POST /api/findings/<id>/promote requires a non-empty reason...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="promote-3.example", title="Needs reason", category=Category.VULNERABILITY.value)
    )
    _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {"refutation": "pass", "reachability": "pass", "trigger": "unsure", "impact": "pass"},
    )
    status, body = _post(f"{base_url}/api/findings/{finding.id}/promote", {"reason": ""})
    assert status == 400
    assert body["code"] == "INVALID_PARAMS"
    print("  [OK]")


def test_promote_finding_validates_related_ids(base_url):
    print("[TEST] POST /api/findings/<id>/promote rejects an unknown related_finding_id...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="promote-4.example", title="Bad related id", category=Category.VULNERABILITY.value)
    )
    _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {"refutation": "pass", "reachability": "pass", "trigger": "demote", "impact": "pass"},
    )
    status, body = _post(
        f"{base_url}/api/findings/{finding.id}/promote",
        {"reason": "chained", "related_finding_ids": ["does-not-exist"]},
    )
    assert status == 400
    assert body["code"] == "INVALID_PARAMS"
    print("  [OK]")


def test_finding_gates_survives_re_sighting(base_url):
    """A gated finding seen again by the tool (same fingerprint) must keep
    its gate verdict -- merge() must never silently reset review state."""
    print("[TEST] gate verdict survives a repeat tool sighting...")
    finding = server.FINDINGS.add(
        Finding(tool="nuclei", target="gates-test-6.example", title="Repeat SQLi", category=Category.VULNERABILITY.value)
    )
    _post(
        f"{base_url}/api/findings/{finding.id}/gates",
        {"refutation": "pass", "reachability": "pass", "trigger": "pass", "impact": "pass"},
    )
    # Same tool/target/title/category/location -> same fingerprint -> merges.
    server.FINDINGS.add(
        Finding(tool="nuclei", target="gates-test-6.example", title="Repeat SQLi", category=Category.VULNERABILITY.value)
    )
    status, body = _get(f"{base_url}/api/findings/{finding.id}")
    assert status == 200
    assert body["finding"]["gate_status"] == "confirmed"
    print("  [OK]")
