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
        "pass", "fail", "demote", "unsure",
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
