"""MCP bridge registration smoke tests."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.api import mcp as M
from nexhunter.api import mcp_profiles as P
from nexhunter.core import tools as T


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
    """Registering another profile picks its tools up without hand-written code."""
    print("[TEST] Registration is registry-driven...")
    before = _tool_names()

    added = M.register_profile_tools("nexhunter-recon")
    after = _tool_names()

    assert added > 0, "the recon profile should contribute tools"
    assert after > before, "registering a profile should expose new tools"
    assert "subfinder_enum" in after, "a recon tool should now be exposed"

    print(f"  [OK] {added} recon tools registered from the registry alone")


def test_no_raw_command_tool():
    """Test the old raw-shell tool is gone."""
    print("[TEST] MCP has no raw command tool...")
    names = _tool_names()
    assert "run_command" not in names
    print("  [OK] run_command removed")


if __name__ == "__main__":
    test_active_profile_tools_exposed()
    test_registration_generated_from_registry()
    test_no_raw_command_tool()
    print("\nAll MCP registration tests passed")
