"""Comprehensive tests for all NexHunter features."""

import sys
import json
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.api.security_features import (
    OsintCollector,
    VulnerabilityAnalyzer,
    BugBountyAssessment,
    CTFChallengeAnalyzer,
    ThreatIntelligence,
)
from nexhunter.api.visual import VulnerabilityCard, ProgressTracker, DashboardMetrics
from nexhunter.workflows.security_workflows import (
    BugBountyWorkflow,
    PenetrationTestingWorkflow,
    RedTeamWorkflow,
    SecurityAuditWorkflow,
    ApiSecurityWorkflow,
    MobileSecurityWorkflow,
    CloudSecurityWorkflow,
    SupplyChainSecurityWorkflow,
    DevSecOpsWorkflow,
    WORKFLOW_TYPES,
)
from nexhunter.agents.enhanced import ENHANCED_AGENTS
from nexhunter.workflows.workflow_agents import WORKFLOW_AGENTS


def test_osint_collector():
    """Test OSINT collector."""
    print("[TEST] OSINT Collector...")
    collector = OsintCollector()
    collector.add_subdomain("test.example.com", "1.2.3.4")
    collector.add_email("test@example.com", "source")
    collector.add_social("twitter", "handle", "url")

    data = collector.to_dict()
    assert len(data["subdomains"]) > 0
    assert len(data["emails"]) > 0
    assert len(data["social_media"]) > 0
    print("  [OK] OSINT Collector working")


def test_vulnerability_analyzer():
    """Test vulnerability analyzer."""
    print("[TEST] Vulnerability Analyzer...")
    analyzer = VulnerabilityAnalyzer()
    analyzer.add_vulnerability("SQL Injection", "CWE-89", 9.8, "critical", "DB compromise")
    analyzer.add_vulnerability("XSS", "CWE-79", 7.1, "high", "Cookie theft")

    threat = analyzer.threat_score()
    assert threat.level in ["critical", "high", "medium", "low", "info"]
    assert threat.score >= 0 and threat.score <= 100
    print("  [OK] Vulnerability Analyzer working")


def test_bug_bounty_assessment():
    """Test bug bounty assessment."""
    print("[TEST] Bug Bounty Assessment...")
    assessment = BugBountyAssessment("example.com")
    assessment.set_scope(["example.com"], [])

    for phase in list(assessment.phases.keys())[:3]:
        assessment.start_phase(phase)
        assessment.complete_phase(phase, 1)

    summary = assessment.to_dict()
    assert summary["target"] == "example.com"
    print("  [OK] Bug Bounty Assessment working")


def test_ctf_analyzer():
    """Test CTF analyzer."""
    print("[TEST] CTF Analyzer...")
    analyzer = CTFChallengeAnalyzer("web")
    analyzer.add_hint("Check for SQLi")

    data = analyzer.to_dict()
    assert data["type"] == "web"
    assert len(data["tools"]) > 0
    print("  [OK] CTF Analyzer working")


def test_threat_intelligence():
    """Test threat intelligence."""
    print("[TEST] Threat Intelligence...")
    intel = ThreatIntelligence()
    intel.add_ioc("IP", "1.2.3.4")
    intel.add_ttp("Recon", "Active Scanning")
    intel.add_mitre_technique("T1046", "Network Service Discovery")

    risk = intel.assess_risk()
    assert "risk_level" in risk
    assert "risk_score" in risk
    print("  [OK] Threat Intelligence working")


def test_vulnerability_card():
    """Test vulnerability card."""
    print("[TEST] Vulnerability Card...")
    card = VulnerabilityCard(
        title="SQLi",
        severity="critical",
        endpoint="/search",
        impact="DB compromise",
        remediation="Use parameterized queries",
    )

    data = card.to_dict()
    assert data["title"] == "SQLi"
    assert data["severity"] == "critical"
    print("  [OK] Vulnerability Card working")


def test_progress_tracker():
    """Test progress tracker."""
    print("[TEST] Progress Tracker...")
    tracker = ProgressTracker(100)
    tracker.increment(25, "Phase 1")
    tracker.increment(25, "Phase 2")

    assert tracker.percent() == 50
    assert tracker.step == "Phase 2"
    print("  [OK] Progress Tracker working")


def test_dashboard_metrics():
    """Test dashboard metrics."""
    print("[TEST] Dashboard Metrics...")
    metrics = DashboardMetrics()
    metrics.requests = 10
    metrics.findings = 5
    metrics.processes = 2

    data = metrics.to_dict()
    assert data["requests"] == 10
    assert data["findings"] == 5
    print("  [OK] Dashboard Metrics working")


# These four tests used to wrap their assertions in try/except and return
# False on failure. Under pytest a returned value is ignored, so a broken
# workflow still reported as passing -- the tests could not fail. Assertions
# now propagate, which is the only thing pytest treats as a failure.

def test_workflows():
    """Test all workflows."""
    print("[TEST] Workflows...")
    target = "example.com"

    assert WORKFLOW_TYPES, "no workflows registered"
    for wf_type, wf_class in WORKFLOW_TYPES.items():
        workflow = wf_class(target)
        assert hasattr(workflow, "phases"), f"{wf_type} has no phases attribute"
        assert len(workflow.phases) > 0, f"{wf_type} defines no phases"

    print(f"  [OK] {len(WORKFLOW_TYPES)} workflows define phases")


def test_enhanced_agents():
    """Test enhanced agents."""
    print("[TEST] Enhanced Agents...")

    assert ENHANCED_AGENTS, "no enhanced agents registered"
    for agent_name, agent in ENHANCED_AGENTS.items():
        assert hasattr(agent, "name"), f"{agent_name} has no name"
        assert hasattr(agent, "execute"), f"{agent_name} has no execute()"
        assert agent.name, f"{agent_name} has an empty name"

    print(f"  [OK] {len(ENHANCED_AGENTS)} enhanced agents well-formed")


def test_workflow_agents():
    """Test workflow agents."""
    print("[TEST] Workflow Agents...")

    assert WORKFLOW_AGENTS, "no workflow agents registered"
    for agent_name, agent in WORKFLOW_AGENTS.items():
        assert hasattr(agent, "name"), f"{agent_name} has no name"
        assert hasattr(agent, "execute"), f"{agent_name} has no execute()"
        result = agent.execute(None, {"target": "example.com"})
        assert "ok" in result, f"{agent_name} returned no 'ok' key: {result}"

    print(f"  [OK] {len(WORKFLOW_AGENTS)} workflow agents respond")


def test_integration():
    """Test integration scenarios."""
    print("[TEST] Integration Scenarios...")

    # Bug bounty workflow with OSINT
    BugBountyWorkflow("example.com")
    osint = OsintCollector()
    osint.add_subdomain("app.example.com", "1.2.3.4")
    assert len(osint.to_dict()["subdomains"]) > 0

    # API workflow with vulnerability analysis
    ApiSecurityWorkflow("https://api.example.com")
    analyzer = VulnerabilityAnalyzer()
    analyzer.add_vulnerability("API Auth Bypass", "CWE-287", 9.1, "critical", "Access")
    chains = analyzer.detect_chains()
    assert chains is not None, "detect_chains should return a result, not None"

    # Cloud workflow with threat intel
    CloudSecurityWorkflow("aws-account")
    intel = ThreatIntelligence()
    intel.add_ioc("S3_BUCKET", "public-bucket")
    risk = intel.assess_risk()
    assert "risk_level" in risk

    print("  [OK] All integration scenarios working")


def run_all_tests():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("NexHunter Feature Tests")
    print("=" * 60 + "\n")

    tests = [
        test_osint_collector,
        test_vulnerability_analyzer,
        test_bug_bounty_assessment,
        test_ctf_analyzer,
        test_threat_intelligence,
        test_vulnerability_card,
        test_progress_tracker,
        test_dashboard_metrics,
        test_workflows,
        test_enhanced_agents,
        test_workflow_agents,
        test_integration,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            result = test()
            if result is not False:
                passed += 1
        except Exception as e:
            print(f"  ERROR: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60 + "\n")

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
