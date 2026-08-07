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
