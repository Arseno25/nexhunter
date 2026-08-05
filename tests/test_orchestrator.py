"""Autonomous orchestration, target profiling, and adaptive planning.

Uses a fake execution service so the loop can be exercised without installed
security binaries, and so a test can assert exactly which tools the planner
chose and that none exceeded the risk ceiling.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.agents.profiler import Profiler
from nexhunter.core import tools as T
from nexhunter.core.risk import RiskLevel
from nexhunter.findings.store import FindingStore
from nexhunter.workflows.orchestrator import (
    AdaptivePlanner,
    AutonomousOrchestrator,
    RunStatus,
)


class FakeExecutionService:
    """Stands in for ExecutionService.

    Records every call, so a test can prove which tools ran and that a tool
    the fake refuses is treated as a non-fatal skip. `denied` names tools this
    fake reports as failing, standing in for a tool error.
    """

    def __init__(self, outputs=None, denied=None):
        self.calls = []
        self.outputs = outputs or {}
        self.denied = set(denied or [])

    def execute(self, tool_name, params, **kwargs):
        self.calls.append({"tool": tool_name, "params": params})
        if tool_name in self.denied:
            return {"ok": False, "code": "TOOL_ERROR", "error": "tool refused",
                    "execution_id": f"exec-{len(self.calls)}"}
        return {
            "ok": True,
            "status": "completed",
            "execution_id": f"exec-{len(self.calls)}",
            "output": self.outputs.get(tool_name, ""),
        }

    def tools_called(self):
        return [c["tool"] for c in self.calls]


# --------------------------------------------------------------------------
# Profiler
# --------------------------------------------------------------------------

def test_profiler_records_evidence_not_guesses():
    """Every observation carries the tool that produced it."""
    print("[TEST] Profiler attaches evidence...")
    profiler = Profiler()
    profile = profiler.new_profile("https://example.com")

    profiler.observe(profile, "httpx_probe",
                     [{"status": 200, "title": "Home", "tech": ["nginx", "WordPress"]}],
                     execution_id="exec-1")

    techs = profile.technology_names()
    assert "nginx" in techs and "wordpress" in techs
    for observation in profile.technologies:
        assert observation.evidence.source == "httpx_probe", "tech must name its source"
        assert observation.evidence.execution_id == "exec-1"

    print("  [OK] Observations are evidenced")


def test_profiler_distinguishes_web_surface():
    """A web surface is inferred only from actual evidence."""
    print("[TEST] Profiler detects a web surface from evidence...")
    profiler = Profiler()

    bare = profiler.new_profile("example.com")
    assert not bare.has_web_surface(), "a bare domain with no evidence has no known web surface"

    profiled = profiler.new_profile("example.com")
    profiler.observe(profiled, "nmap_scan",
                     {"hosts": [{"ports": [{"port": 443, "service": "https"}]}]})
    assert profiled.has_web_surface(), "an open 443 is evidence of a web surface"
    assert 443 in profiled.open_ports()

    print("  [OK] Web surface inferred from evidence only")


def test_profiler_ignores_empty_output():
    """A tool that produced nothing adds nothing."""
    print("[TEST] Profiler ignores empty output...")
    profiler = Profiler()
    profile = profiler.new_profile("example.com")
    before = len(profile.observations)
    profiler.observe(profile, "httpx_probe", None)
    assert len(profile.observations) == before
    print("  [OK] No phantom observations")


# --------------------------------------------------------------------------
# Planner adaptation
# --------------------------------------------------------------------------

def test_planner_seeds_by_target_type():
    """The first plan depends on what kind of target it is."""
    print("[TEST] Planner seeds by target type...")
    planner = AdaptivePlanner()
    profiler = Profiler()

    web = planner.plan(profiler.new_profile("https://example.com"), [], RiskLevel.ACTIVE)
    assert any(s.tool == "httpx_probe" for s in web), "a web target should probe HTTP first"

    host = planner.plan(profiler.new_profile("192.168.1.10"), [], RiskLevel.ACTIVE)
    assert any(s.tool == "nmap_scan" for s in host), "a host should get a service scan"

    print("  [OK] Seed plan matches target type")


def test_planner_adapts_to_wordpress():
    """Detecting WordPress pulls a WordPress scan into the plan.

    This is the real-time adaptation: the plan changes because the profile did.
    """
    print("[TEST] Planner adapts to observed technology...")
    planner = AdaptivePlanner()
    profiler = Profiler()
    profile = profiler.new_profile("https://example.com")

    before = [s.tool for s in planner.plan(profile, ["httpx_probe"], RiskLevel.ACTIVE)]
    assert "wpscan_scan" not in before, "no WordPress evidence yet"

    profiler.observe(profile, "httpx_probe", [{"status": 200, "tech": ["WordPress"]}])
    after = [s.tool for s in planner.plan(profile, ["httpx_probe"], RiskLevel.ACTIVE)]
    assert "wpscan_scan" in after, "WordPress evidence should pull in wpscan"

    print("  [OK] Plan adapts to new evidence")


def test_planner_does_not_repeat_completed_tools():
    """A tool already run is not planned again."""
    print("[TEST] Planner does not repeat work...")
    planner = AdaptivePlanner()
    profile = Profiler().new_profile("https://example.com")

    plan = planner.plan(profile, ["httpx_probe", "dns_lookup", "whatweb_scan"], RiskLevel.ACTIVE)
    assert "httpx_probe" not in [s.tool for s in plan]

    print("  [OK] Completed tools excluded")


# --------------------------------------------------------------------------
# Methodology planner (recommend_plan)
# --------------------------------------------------------------------------

def test_recommend_plan_phases_in_order():
    """A recommended plan walks the methodology in order, recon first."""
    print("[TEST] Recommend plan follows the methodology...")
    rec = AdaptivePlanner().recommend("https://example.com")

    assert list(rec["phases"]) == [
        "recon", "enumeration", "web_enum", "assessment"
    ], rec["phases"]
    assert rec["withheld"], "intrusive follow-ups are planned but withheld"

    all_tools = [s["tool"] for steps in rec["phases"].values() for s in steps]
    assert all_tools[0] == "dns_lookup", "the very first step is DNS"
    assert all_tools[1] == "whois_lookup", "WHOIS follows DNS"
    assert "nmap_scan" in all_tools, "enumeration scans services"

    print("  [OK] 4 phases, recon-first, exploitation withheld")


def test_recommend_plan_withholds_intrusive():
    """Exploitation steps are surfaced for a human, never planned to run."""
    print("[TEST] Intrusive steps withheld...")
    rec = AdaptivePlanner().recommend("https://example.com")

    planned = {s["tool"] for steps in rec["phases"].values() for s in steps}
    withheld = {w["tool"] for w in rec["withheld"]}
    for tool in ("sqlmap_scan", "ffuf_scan", "dalfox_xss"):
        assert tool in withheld, f"{tool} should be withheld"
        assert tool not in planned, f"{tool} must not be auto-planned"
    for w in rec["withheld"]:
        assert w["risk_level"] == "intrusive", "only intrusive tools are withheld"
        assert w["requires"] == "human approval"

    print("  [OK] Intrusive tools planned, not scheduled")


def test_recommend_plan_gates_tls_on_scheme():
    """TLS assessment only when the target speaks HTTPS."""
    print("[TEST] TLS phase gated on scheme...")
    planner = AdaptivePlanner()

    https = planner.recommend("https://example.com")
    https_tools = {s["tool"] for steps in https["phases"].values() for s in steps}
    assert {"testssl", "sslyze"} <= https_tools, "HTTPS target gets TLS review"

    http = planner.recommend("http://example.com")
    http_tools = {s["tool"] for steps in http["phases"].values() for s in steps}
    assert not ({"testssl", "sslyze"} & http_tools), "plain HTTP skips TLS review"

    print("  [OK] TLS assessment follows the scheme")


def test_recommend_plan_host_skips_web_phases():
    """A bare host with no web evidence gets no web enumeration or TLS."""
    print("[TEST] Bare host plan stays host-shaped...")
    rec = AdaptivePlanner().recommend("192.168.1.10")

    names = list(rec["phases"])
    assert names == ["recon", "enumeration"], names
    tools = {s["tool"] for steps in rec["phases"].values() for s in steps}
    assert "katana_crawl" not in tools and "testssl" not in tools

    print("  [OK] Host plan: recon + enumeration only")


# --------------------------------------------------------------------------
# Autonomous loop
# --------------------------------------------------------------------------

def test_autonomous_run_completes_and_adapts():
    """A full run drives the fake service, adapting as output arrives."""
    print("[TEST] Autonomous run completes and adapts...")
    fake = FakeExecutionService(outputs={
        # httpx reports WordPress, which should pull wpscan into a later plan.
        "httpx_probe": '{"status": 200, "title": "Blog", "tech": ["WordPress"]}',
    })
    # httpx's parser expects JSON lines; register the output under its parser.
    orchestrator = AutonomousOrchestrator(execution_service=fake, finding_store=FindingStore())

    run = orchestrator.start(
        target="https://example.com",
        risk_ceiling="active",
        max_steps=15,
        run_async=False,
    )

    assert run.status is RunStatus.COMPLETED, f"run did not complete: {run.errors}"
    assert run.steps_taken > 0, "the run should have executed something"
    called = fake.tools_called()
    assert "httpx_probe" in called, "a web target should have been probed"
    assert run.progress == 100
    assert run.profile is not None

    print(f"  [OK] Ran {run.steps_taken} steps: {called}")


def test_autonomous_never_exceeds_risk_ceiling():
    """Intrusive and destructive tools are never auto-executed.

    This is the line that keeps autonomy from being an attack platform: the
    loop runs passive and active, and surfaces anything heavier for approval.
    """
    print("[TEST] Autonomous run respects the risk ceiling...")
    fake = FakeExecutionService()
    orchestrator = AutonomousOrchestrator(execution_service=fake, finding_store=FindingStore())

    run = orchestrator.start(
        target="https://example.com",
        risk_ceiling="active",
        max_steps=25,
        run_async=False,
    )

    for tool_name in fake.tools_called():
        spec = T.get_tool_spec(tool_name)
        level = RiskLevel(spec.risk_level)
        assert level in (RiskLevel.PASSIVE, RiskLevel.ACTIVE), (
            f"autonomous run executed {tool_name} at {spec.risk_level}, above the ceiling"
        )

    print(f"  [OK] {len(fake.tools_called())} tools ran, none above active")


def test_ceiling_is_clamped_even_if_intrusive_requested():
    """Asking for an intrusive ceiling does not grant one."""
    print("[TEST] Requested intrusive ceiling is clamped...")
    fake = FakeExecutionService()
    orchestrator = AutonomousOrchestrator(execution_service=fake, finding_store=FindingStore())

    run = orchestrator.start(
        target="https://example.com",
        risk_ceiling="destructive",   # asking for the worst
        max_steps=25,
        run_async=False,
    )

    assert run.risk_ceiling == "active", "the ceiling must be clamped to active"
    for tool_name in fake.tools_called():
        assert RiskLevel(T.get_tool_spec(tool_name).risk_level) in (
            RiskLevel.PASSIVE, RiskLevel.ACTIVE
        )

    print("  [OK] Ceiling clamped regardless of request")


def test_denied_step_is_recorded_not_fatal():
    """A failing tool mid-run is recorded and the run continues."""
    print("[TEST] Failed step does not abort the run...")
    fake = FakeExecutionService(denied={"nuclei_scan"})
    orchestrator = AutonomousOrchestrator(execution_service=fake, finding_store=FindingStore())

    run = orchestrator.start(
        target="https://example.com", risk_ceiling="active", max_steps=15, run_async=False,
    )

    assert run.status is RunStatus.COMPLETED, "a failure should not fail the whole run"
    if "nuclei_scan" in fake.tools_called():
        assert any(e.get("tool") == "nuclei_scan" for e in run.errors), (
            "the failure should be recorded"
        )

    print("  [OK] Failure recorded, run continued")


def test_step_budget_is_honored():
    """The loop stops at the step budget."""
    print("[TEST] Step budget honored...")
    fake = FakeExecutionService()
    orchestrator = AutonomousOrchestrator(execution_service=fake, finding_store=FindingStore())

    run = orchestrator.start(
        target="https://example.com", risk_ceiling="active", max_steps=2, run_async=False,
    )

    assert run.steps_taken <= 2, f"budget of 2 exceeded: {run.steps_taken}"
    assert len(fake.calls) <= 2

    print(f"  [OK] Stopped at {run.steps_taken} steps")


# --------------------------------------------------------------------------
# AI-proposed plan
# --------------------------------------------------------------------------

def test_ai_plan_is_validated_and_ceiling_filtered():
    """A proposed plan is reviewed without running anything.

    Valid steps are approved, intrusive steps are withheld for a human, and
    unknown tools or invalid parameters are rejected outright. This is the
    plan-first contract: the AI writes the plan, the registry and the ceiling
    filter it before anything touches the OS.
    """
    print("[TEST] AI plan validated and filtered...")
    fake = FakeExecutionService()
    orchestrator = AutonomousOrchestrator(execution_service=fake, finding_store=FindingStore())

    review = orchestrator.review_plan(
        "https://example.com",
        [
            {"tool": "nmap_scan", "params": {"target": "example.com", "ports": "80,443"}},
            {"tool": "sqlmap_scan", "params": {"url": "https://example.com"}},
            {"tool": "not_a_tool", "params": {}},
            {"tool": "nmap_scan", "params": {"target": "; rm -rf /"}},
        ],
        "active",
    )

    assert [s["tool"] for s in review["approved"]] == ["nmap_scan"], review
    assert [s["tool"] for s in review["withheld"]] == ["sqlmap_scan"], review
    assert review["withheld"][0]["risk_level"] == "intrusive"
    assert len(review["invalid"]) == 2, review
    assert fake.calls == [], "review must not execute anything"

    print("  [OK] Approved 1, withheld 1 (intrusive), rejected 2, nothing ran")


def test_ai_plan_executes_only_approved_steps():
    """A run with steps executes exactly them, re-validated, ceiling-clamped."""
    print("[TEST] AI plan executes only approved steps...")
    fake = FakeExecutionService()
    orchestrator = AutonomousOrchestrator(execution_service=fake, finding_store=FindingStore())

    run = orchestrator.start(
        target="https://example.com",
        risk_ceiling="active",
        max_steps=10,
        run_async=False,
        steps=[
            {"tool": "nmap_scan", "params": {"target": "example.com"}},
            {"tool": "sqlmap_scan", "params": {"url": "https://example.com"}},
            {"tool": "not_a_tool", "params": {}},
            {"tool": "nmap_scan", "params": {"target": "bad target !"}},
        ],
    )

    assert run.status is RunStatus.COMPLETED, run.errors
    assert fake.tools_called() == ["nmap_scan"], fake.tools_called()
    assert run.plan is not None
    assert [w["tool"] for w in run.withheld] == ["sqlmap_scan"], "intrusive step withheld"

    print("  [OK] Ran only the valid, within-ceiling step")


def test_async_run_is_pollable():
    """An async run returns immediately and can be polled to completion."""
    print("[TEST] Async run is pollable...")
    fake = FakeExecutionService()
    orchestrator = AutonomousOrchestrator(execution_service=fake, finding_store=FindingStore())

    run = orchestrator.start(
        target="https://example.com", risk_ceiling="active", max_steps=8, run_async=True,
    )
    assert orchestrator.get_run(run.id) is not None

    for _ in range(100):
        current = orchestrator.get_run(run.id)
        if current.status is not RunStatus.RUNNING:
            break
        time.sleep(0.05)

    assert orchestrator.get_run(run.id).status is RunStatus.COMPLETED

    print("  [OK] Async run polled to completion")


if __name__ == "__main__":
    print("\n=== Autonomous Orchestration Tests ===\n")
    test_profiler_records_evidence_not_guesses()
    test_profiler_distinguishes_web_surface()
    test_profiler_ignores_empty_output()
    test_planner_seeds_by_target_type()
    test_planner_adapts_to_wordpress()
    test_planner_does_not_repeat_completed_tools()
    test_recommend_plan_phases_in_order()
    test_recommend_plan_withholds_intrusive()
    test_recommend_plan_gates_tls_on_scheme()
    test_recommend_plan_host_skips_web_phases()
    test_autonomous_run_completes_and_adapts()
    test_autonomous_never_exceeds_risk_ceiling()
    test_ceiling_is_clamped_even_if_intrusive_requested()
    test_denied_step_is_recorded_not_fatal()
    test_step_budget_is_honored()
    test_ai_plan_is_validated_and_ceiling_filtered()
    test_ai_plan_executes_only_approved_steps()
    test_async_run_is_pollable()
    print("\n=== All Autonomous Orchestration Tests Passed ===\n")
