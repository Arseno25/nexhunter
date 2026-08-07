"""MCP bridge registration smoke tests."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.api import mcp as M
from nexhunter.api import mcp_profiles as P


def _tool_names():
    tools = asyncio.run(M.mcp.list_tools())
    return {t.name for t in tools}


def test_active_profile_tools_exposed():
    """The active profile's registry tools, plus the helpers, are registered.

    Tools are generated from the registry and filtered by profile, so the
    contract is "everything this profile selects", not "everything registered".
    """
    print("[TEST] MCP exposes the active profile...")
    names = _tool_names()

    expected = P.tools_for(P.get_profile(M.PROFILE_NAME))
    for tool_name in expected:
        assert tool_name in names, f"{tool_name} in the active profile but missing from MCP"

    # Core convenience tools are present regardless of profile.
    for helper in ("run_tool", "server_status", "assess", "probe", "recon", "list_profiles"):
        assert helper in names, f"{helper} missing from MCP"

    print(f"  [OK] {len(names)} MCP tools registered for '{M.PROFILE_NAME}'")


def test_registration_generated_from_registry():
    """Registering a profile picks its tools up without hand-written code.

    The default profile is nexhunter-full, so a focused profile's tools are
    already exposed; the contract is that registration is registry-driven
    (the returned count matches the profile) and that a re-registration
    replaces the previous selection instead of stacking on top of it.
    """
    print("[TEST] Registration is registry-driven...")
    before = _tool_names()
    helpers = before - set(M._REGISTRY_TOOLS)

    count = M.register_profile_tools("nexhunter-recon")
    after = _tool_names()

    expected = P.tools_for(P.get_profile("nexhunter-recon"))
    assert count == len(expected), "register_profile_tools should report the profile size"
    for name in expected:
        assert name in after, f"{name} in the recon profile but missing from MCP"

    # A re-registration replaces the selection: the recon tools plus the
    # hand-written helpers remain, registry tools outside the profile do not.
    assert after == set(expected) | helpers, (
        "registering a focused profile should replace, not stack, the selection"
    )
    assert "subfinder_enum" in after, "a recon tool should be exposed"

    print(f"  [OK] {count} recon tools covered, registry-driven and replacing")


def test_no_raw_command_tool():
    """Test the old raw-shell tool is gone."""
    print("[TEST] MCP has no raw command tool...")
    names = _tool_names()
    assert "run_command" not in names
    print("  [OK] run_command removed")


def test_gap_closing_tools_are_registered():
    """submit_presubmission_checklist and promote_finding must be reachable
    the same way the rest of the finding-validation surface is -- as
    hand-written MCP tools, always registered regardless of --profile."""
    print("[TEST] submit_presubmission_checklist and promote_finding are registered...")
    names = _tool_names()
    assert "submit_presubmission_checklist" in names
    assert "promote_finding" in names
    print("  [OK]")


def test_second_pass_gap_closing_tools_are_registered():
    """custody/ledger/triage/chain tools -- the batch of gaps closed in the
    second audit pass -- must be reachable the same way."""
    print("[TEST] custody/ledger/triage/chain tools are registered...")
    names = _tool_names()
    for tool in ("get_finding_custody", "verify_ledger", "triage_findings", "link_finding_chain", "get_finding_chain"):
        assert tool in names, f"{tool} not registered"
    print("  [OK]")


def test_finding_patterns_resource_has_report_quality_reference():
    """The resource must also carry the report-quality formulas/checklist/
    tone rules added in the second audit pass, not just the first pass's
    attack-vector/false-positive content."""
    print("[TEST] nexhunter://findings/patterns resource has report-quality reference...")
    import json

    payload = json.loads(M.resource_finding_patterns())
    for key in ("title_formula", "title_formula_examples", "impact_statement_formula", "presubmit_checklist", "tone_rules"):
        assert key in payload and payload[key], f"missing or empty: {key}"
    print("  [OK]")


def test_finding_patterns_resource_has_expanded_content():
    """The nexhunter://findings/patterns resource must expose all of the
    curated reference, not just the original two lists."""
    print("[TEST] nexhunter://findings/patterns resource has the full reference...")
    import json

    payload = json.loads(M.resource_finding_patterns())
    for key in (
        "attack_vectors", "universal_patterns", "framework_antipatterns",
        "always_rejected", "safe_patterns", "common_false_positives",
        "impact_tiers", "severity_escalation",
    ):
        assert key in payload and payload[key], f"missing or empty: {key}"
    print("  [OK]")


def test_bugbounty_hunt_prompt_is_discoverable():
    """The bug-bounty skill is an MCP prompt: any client that connects sees
    it via the standard prompt-listing capability, no separate config beyond
    the MCP server pointer every client already needs."""
    print("[TEST] bugbounty_hunt prompt is registered and discoverable...")
    prompts = asyncio.run(M.mcp.list_prompts())
    names = {p.name for p in prompts}
    assert "bugbounty_hunt" in names
    print("  [OK] bugbounty_hunt discoverable via list_prompts")


def test_bugbounty_hunt_prompt_reflects_live_registry():
    """Tool names in the rendered prompt must be real, registered tools --
    the phases are generated from the registry, never hardcoded, so they
    can't drift out of sync with what's actually available."""
    print("[TEST] bugbounty_hunt prompt only names real, registered tools...")
    rendered = M.bugbounty_hunt("https://example.com")
    assert "https://example.com" in rendered
    import re

    non_tool_words = {
        "run_tool", "get_finding", "submit_finding_gates", "score_cvss", "bounty_report",
        "submit_presubmission_checklist", "promote_finding",
        "pass", "fail", "demote", "unsure", "confirmed", "lead",
    }
    named = set(re.findall(r"`([a-z][a-z0-9_]+)`", rendered)) - non_tool_words
    from nexhunter.core import tools as T

    unknown = named - set(T.TOOLS)
    assert not unknown, f"prompt names tools that aren't registered: {unknown}"
    print(f"  [OK] {len(named)} tool names in the prompt, all present in the registry")


if __name__ == "__main__":
    test_active_profile_tools_exposed()
    test_registration_generated_from_registry()
    test_no_raw_command_tool()
    test_bugbounty_hunt_prompt_is_discoverable()
    test_bugbounty_hunt_prompt_reflects_live_registry()
    print("\nAll MCP registration tests passed")
