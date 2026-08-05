"""Intelligent tool selection: scoring, capping, gating, and the plan-first API.

The selector must draw a small, high-value shortlist from the full registry --
never the whole thing -- and it must respect the same evidence gates and risk
ceiling the methodology planner does.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.agents.profiler import Profiler
from nexhunter.agents.selector import ToolSelector, OBJECTIVES, TARGET_TYPE_CATEGORIES
from nexhunter.core import tools as T
from nexhunter.core.risk import RiskLevel
from nexhunter.findings.store import FindingStore
from nexhunter.workflows.orchestrator import AutonomousOrchestrator, RunStatus

from test_orchestrator import FakeExecutionService


def _web_profile():
    return Profiler().new_profile("https://example.com")


# --------------------------------------------------------------------------
# Scoring & capping
# --------------------------------------------------------------------------

def test_selector_draws_a_capped_shortlist_not_everything():
    """A selection is a small subset, never the whole 252-tool registry."""
    print("[TEST] Selection caps to a shortlist...")
    result = ToolSelector().select(_web_profile(), "standard", RiskLevel.ACTIVE)
    assert result.considered == len(T.TOOLS)
    assert 0 < len(result.selected) <= OBJECTIVES["standard"].cap
    assert len(result.selected) < result.considered, "must not select everything"
    print(f"  [OK] {len(result.selected)}/{result.considered} selected")


def test_selector_quick_is_smaller_than_comprehensive():
    """Objective controls breadth: quick << comprehensive."""
    print("[TEST] Objective breadth ordering...")
    sel, p = ToolSelector(), _web_profile()
    quick = sel.select(p, "quick", RiskLevel.ACTIVE)
    comprehensive = sel.select(p, "comprehensive", RiskLevel.ACTIVE)
    assert len(quick.selected) <= OBJECTIVES["quick"].cap
    assert len(quick.selected) <= len(comprehensive.selected)
    print(f"  [OK] quick={len(quick.selected)} <= comprehensive={len(comprehensive.selected)}")


def test_selector_web_target_selects_web_tools():
    """A web target's shortlist is dominated by web-surface tooling."""
    print("[TEST] Web target -> web tools...")
    result = ToolSelector().select(_web_profile(), "standard", RiskLevel.ACTIVE)
    cats = {s.category for s in result.selected}
    assert "web" in cats, cats
    assert any(s.name == "httpx_probe" for s in result.selected), "should probe HTTP"
    print(f"  [OK] categories: {sorted(cats)}")


def test_selector_host_skips_web_tools():
    """A bare host gets network/recon tooling, not web tooling."""
    print("[TEST] Host target skips web tools...")
    host = Profiler().new_profile("192.168.1.10")
    result = ToolSelector().select(host, "standard", RiskLevel.ACTIVE)
    cats = {s.category for s in result.selected}
    assert "web" not in cats and "api" not in cats, cats
    assert any(s.category in ("network", "recon") for s in result.selected)
    print(f"  [OK] categories: {sorted(cats)}")


# --------------------------------------------------------------------------
# Gates: risk ceiling, stealth, technology
# --------------------------------------------------------------------------

def test_selector_withholds_tools_above_ceiling():
    """Intrusive tools never land in 'selected' under an active ceiling."""
    print("[TEST] Ceiling withholds intrusive tools...")
    result = ToolSelector().select(_web_profile(), "comprehensive", RiskLevel.ACTIVE)
    for st in result.selected:
        assert RiskLevel(st.risk_level) in (RiskLevel.PASSIVE, RiskLevel.ACTIVE), st.name
    assert result.withheld, "some tools should be withheld above the ceiling"
    assert all(w.risk_level in ("intrusive", "destructive") for w in result.withheld), \
        "only above-ceiling tools are withheld"
    print(f"  [OK] {len(result.withheld)} withheld, none intrusive selected")


def test_selector_stealth_is_passive_only():
    """The stealth objective yields passive tools exclusively."""
    print("[TEST] Stealth = passive only...")
    result = ToolSelector().select(_web_profile(), "stealth", RiskLevel.ACTIVE)
    assert result.selected, "stealth should still find passive tools"
    assert all(s.risk_level == "passive" for s in result.selected), \
        [s.name for s in result.selected]
    print(f"  [OK] {[s.name for s in result.selected]}")


def test_selector_boosts_tech_specific_tools_on_evidence():
    """WordPress evidence pulls wpscan up; its absence pushes it away."""
    print("[TEST] Technology boost for wpscan...")
    profiler, sel = Profiler(), ToolSelector()

    wp = profiler.new_profile("https://blog.example.com")
    profiler.observe(wp, "httpx_probe", [{"tech": ["WordPress"]}], "e1")
    with_wp = sel.select(wp, "comprehensive", RiskLevel.ACTIVE)

    plain = profiler.new_profile("https://plain.example.com")
    without_wp = sel.select(plain, "comprehensive", RiskLevel.ACTIVE)

    def find(res):
        for st in list(res.selected) + list(res.withheld):
            if st.name == "wpscan_scan":
                return st
        return None

    boosted, baseline = find(with_wp), find(without_wp)
    assert boosted is not None, "wpscan should appear when WordPress is detected"
    if baseline is not None:
        assert boosted.score > baseline.score, "WordPress evidence must boost wpscan"
    print(f"  [OK] wpscan boosted (score {boosted.score:.2f})")


def test_every_category_is_reachable():
    """No registered category is orphaned -- each is selectable for some target."""
    print("[TEST] every category is reachable...")
    all_cats = {s.category for s in T.TOOLS.values()}
    reachable = set()
    for mapping in TARGET_TYPE_CATEGORIES.values():
        reachable |= set(mapping)
    orphaned = all_cats - reachable
    assert not orphaned, f"categories never selectable by any target: {sorted(orphaned)}"
    print(f"  [OK] all {len(all_cats)} categories reachable")


def test_binary_target_selects_binary_tooling():
    """A file target pulls in binary/RE tooling, not web tooling."""
    print("[TEST] binary target -> binary tools...")
    profile = Profiler().new_profile(sys.executable)  # a real file on any OS
    assert profile.target_type == "binary", profile.target_type
    result = ToolSelector().select(profile, "standard", RiskLevel.ACTIVE)
    cats = {s.category for s in result.selected}
    assert "binary" in cats, cats
    assert not ({"web", "api"} & cats), f"no web tools on a binary: {cats}"
    print(f"  [OK] categories: {sorted(cats)}")


def test_cloud_marker_selects_cloud_tooling():
    """An ARN target routes to cloud/container tooling."""
    print("[TEST] cloud marker -> cloud tools...")
    profile = Profiler().new_profile("arn:aws:iam::123456789012:user/alice")
    assert profile.target_type == "cloud", profile.target_type
    result = ToolSelector().select(profile, "comprehensive", RiskLevel.ACTIVE)
    cats = {s.category for s in result.selected}
    assert cats & {"cloud", "container"}, cats
    print(f"  [OK] categories: {sorted(cats)}")


def test_selector_is_deterministic():
    """Same profile + objective -> identical ranking."""
    print("[TEST] Selection is deterministic...")
    sel, p = ToolSelector(), _web_profile()
    a = [s.name for s in sel.select(p, "standard", RiskLevel.ACTIVE).selected]
    b = [s.name for s in sel.select(p, "standard", RiskLevel.ACTIVE).selected]
    assert a == b, "ranking must be reproducible"
    print("  [OK] Stable ordering")


# --------------------------------------------------------------------------
# Plan-first API and the select strategy
# --------------------------------------------------------------------------

def test_select_plan_returns_reviewable_shortlist():
    """select_plan yields a curated, reasoned shortlist without running."""
    print("[TEST] select_plan shape...")
    plan = AutonomousOrchestrator.select_plan("https://example.com", "standard", "active")
    assert plan["considered"] == len(T.TOOLS)
    assert plan["selected_count"] == len(plan["selected"]) <= OBJECTIVES["standard"].cap
    assert plan["phases"], "selected tools are grouped into phases"
    for entry in plan["selected"]:
        assert entry["reasons"], "each pick explains itself"
    print(f"  [OK] {plan['selected_count']} tools, phases {list(plan['phases'])}")


def test_select_strategy_run_respects_ceiling():
    """An autonomous run with strategy='select' never exceeds the ceiling."""
    print("[TEST] select-strategy run stays within ceiling...")
    fake = FakeExecutionService()
    orch = AutonomousOrchestrator(execution_service=fake, finding_store=FindingStore())
    run = orch.start(
        target="https://example.com", risk_ceiling="active", max_steps=6,
        run_async=False, strategy="select", objective="standard",
    )
    assert run.status is RunStatus.COMPLETED, run.errors
    assert run.steps_taken > 0, "the run should have executed something"
    assert run.steps_taken <= 6, "budget honored"
    for tool_name in fake.tools_called():
        spec = T.get_tool_spec(tool_name)
        assert RiskLevel(spec.risk_level) in (RiskLevel.PASSIVE, RiskLevel.ACTIVE), tool_name
    print(f"  [OK] ran {run.steps_taken} tools, all within ceiling")


if __name__ == "__main__":
    test_selector_draws_a_capped_shortlist_not_everything()
    test_selector_quick_is_smaller_than_comprehensive()
    test_selector_web_target_selects_web_tools()
    test_selector_host_skips_web_tools()
    test_selector_withholds_tools_above_ceiling()
    test_selector_stealth_is_passive_only()
    test_selector_boosts_tech_specific_tools_on_evidence()
    test_every_category_is_reachable()
    test_binary_target_selects_binary_tooling()
    test_cloud_marker_selects_cloud_tooling()
    test_selector_is_deterministic()
    test_select_plan_returns_reviewable_shortlist()
    test_select_strategy_run_respects_ceiling()
    print("\nAll selector tests passed.")
