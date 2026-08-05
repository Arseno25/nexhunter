"""MCP profile filtering and registry-generated tool exposure."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.core import tools as T
from nexhunter.api import mcp_profiles as P


def test_all_expected_profiles_exist():
    """The documented profiles are all present."""
    print("[TEST] Expected profiles exist...")
    expected = {
        "nexhunter-core", "nexhunter-recon", "nexhunter-web", "nexhunter-api",
        "nexhunter-code", "nexhunter-cloud", "nexhunter-container",
        "nexhunter-forensics",
    }
    missing = expected - set(P.PROFILES)
    assert not missing, f"missing profiles: {missing}"
    print(f"  [OK] {len(P.PROFILES)} profiles defined")


def test_profile_filters_by_category():
    """A profile exposes only its own categories."""
    print("[TEST] Profiles filter by category...")
    web = P.get_profile("nexhunter-web")
    selected = P.tools_for(web)

    assert selected, "the web profile should expose some tools"
    for name, spec in selected.items():
        assert spec.category in web.categories, (
            f"{name} has category {spec.category!r}, not in {web.categories}"
        )

    # A recon-only tool must not appear in the web profile.
    assert "subfinder_enum" not in selected, "subfinder is recon, not web"

    print(f"  [OK] Web profile exposes {len(selected)} tools, all in-category")


def test_profile_is_smaller_than_full_registry():
    """A focused profile is a fraction of the registry, which is the point."""
    print("[TEST] Profiles shrink the payload...")
    core = P.tools_for(P.get_profile("nexhunter-core"))
    full = P.tools_for(P.get_profile("nexhunter-full"))

    assert len(core) < len(full) / 4, (
        f"core exposes {len(core)} of {len(full)}; the profile is not narrowing much"
    )
    print(f"  [OK] core={len(core)} vs full={len(full)} tools")


def test_no_profile_exposes_destructive_tools():
    """No profile lists a destructive tool, whatever its category."""
    print("[TEST] No profile exposes destructive tools...")
    for profile in P.PROFILES.values():
        for name, spec in P.tools_for(profile).items():
            assert spec.risk_level != "destructive", (
                f"profile {profile.name} exposes destructive tool {name}"
            )
    print("  [OK] No destructive tool in any profile")


def test_default_profile_is_full():
    """No profile selected means the full non-destructive registry."""
    print("[TEST] Default profile is full...")
    default = P.get_profile(None)
    assert default.name == P.DEFAULT_PROFILE == "nexhunter-full"

    selected = P.tools_for(default)
    assert len(selected) == len(P.tools_for(P.get_profile("nexhunter-full")))
    for name, spec in selected.items():
        assert spec.risk_level != "destructive", f"{name} is destructive"

    print(f"  [OK] Default '{default.name}' exposes {len(selected)} non-destructive tools")


def test_unknown_profile_raises():
    """An unknown profile name fails loudly rather than silently exposing everything."""
    print("[TEST] Unknown profile rejected...")
    try:
        P.get_profile("nexhunter-does-not-exist")
        assert False, "expected a KeyError for an unknown profile"
    except KeyError as exc:
        assert "known profiles" in str(exc)
    print("  [OK] Unknown profile raises")


def test_every_tool_has_category_risk_and_maturity():
    """Registry metadata is complete, since profiles depend on it."""
    print("[TEST] Registry metadata complete...")
    valid_risk = {"passive", "active", "intrusive", "destructive"}
    valid_maturity = {"stable", "beta", "experimental", "disabled"}

    for name, spec in T.TOOLS.items():
        assert spec.category, f"{name} has no category"
        assert spec.risk_level in valid_risk, f"{name} has risk {spec.risk_level!r}"
        assert spec.maturity in valid_maturity, f"{name} has maturity {spec.maturity!r}"

    print(f"  [OK] {len(T.TOOLS)} tools carry complete metadata")


def test_stable_tools_are_declared_not_guessed():
    """Stable status is asserted per tool, never inferred."""
    print("[TEST] Stable maturity is declared...")
    stable = {name for name, spec in T.TOOLS.items() if spec.maturity == "stable"}

    assert stable, "expected some stable tools"
    assert stable <= set(T.STABLE_TOOLS), (
        f"tools claim stable without being declared: {stable - set(T.STABLE_TOOLS)}"
    )
    assert 15 <= len(T.STABLE_TOOLS) <= 40, (
        f"the stable set should stay a curated 20-30, found {len(T.STABLE_TOOLS)}"
    )

    # Every declared-stable name must actually exist. Declaring a tool stable
    # that is not registered is precisely the kind of unverified claim this
    # project exists to stop making.
    phantom = sorted(set(T.STABLE_TOOLS) - set(T.TOOLS))
    assert not phantom, f"declared stable but not registered: {phantom}"

    print(f"  [OK] {len(stable)} declared-stable tools, all registered")


def test_mcp_registers_only_profile_tools():
    """The MCP server registers the active profile's tools, not the whole registry."""
    print("[TEST] MCP registers only the active profile...")
    from nexhunter.api import mcp as bridge

    registered = {tool.name for tool in asyncio.run(bridge.mcp.list_tools())}
    profile = P.get_profile(bridge.PROFILE_NAME)
    expected_registry_tools = P.tools_for(profile)

    # Registry tools that should not be in this profile are absent.
    leaked = [
        name for name in T.TOOLS
        if name in registered and name not in expected_registry_tools
    ]
    assert not leaked, f"tools registered outside the active profile: {leaked[:5]}"

    # Workflow tools (assess, findings, list_profiles...) are always present.
    for workflow_tool in ["list_profiles", "tool_info", "executions", "server_status"]:
        assert workflow_tool in registered, f"missing workflow tool {workflow_tool}"

    print(f"  [OK] {len(registered)} MCP tools registered for '{profile.name}'")


def test_mcp_exposes_resources():
    """Read-only resources are registered so clients need not spend tool calls."""
    print("[TEST] MCP resources registered...")
    from nexhunter.api import mcp as bridge

    resources = asyncio.run(bridge.mcp.list_resources())
    uris = {str(resource.uri) for resource in resources}

    for expected in [
        "nexhunter://tools",
        "nexhunter://tools/stable",
        "nexhunter://profiles",
        "nexhunter://executions",
        "nexhunter://findings",
        "nexhunter://system/status",
    ]:
        assert expected in uris, f"missing resource {expected}; have {sorted(uris)}"

    print(f"  [OK] {len(uris)} resources registered")


def test_tool_limit_respects_client_cap():
    """A tool limit culls the payload instead of bypassing the client's cap."""
    print("[TEST] Tool limit culls the payload...")
    from nexhunter.api import mcp as bridge

    full = P.tools_for(P.get_profile("nexhunter-full"))
    assert len(full) > 50, "the full profile must exceed any sane limit for this test"

    picked = bridge._select_for_limit(full, 30)
    assert len(picked) == 30, f"expected 30 tools, got {len(picked)}"

    # A profile under the limit is returned untouched.
    assert bridge._select_for_limit(full, None) == full
    assert bridge._select_for_limit(full, len(full)) == full

    # Stability is preferred: a stable tool must survive a cull that removes
    # experimental ones.
    stable_names = [n for n, s in full.items() if s.maturity == "stable"]
    experimental_names = [n for n, s in full.items() if s.maturity == "experimental"]
    if stable_names and experimental_names:
        assert stable_names[0] in picked, "stable tool should outrank experimental"
    print(f"  [OK] limit 30 -> {len(picked)} tools, stable-first")


if __name__ == "__main__":
    print("\n=== MCP Profile Tests ===\n")
    test_all_expected_profiles_exist()
    test_profile_filters_by_category()
    test_profile_is_smaller_than_full_registry()
    test_no_profile_exposes_destructive_tools()
    test_default_profile_is_full()
    test_unknown_profile_raises()
    test_every_tool_has_category_risk_and_maturity()
    test_stable_tools_are_declared_not_guessed()
    test_mcp_registers_only_profile_tools()
    test_mcp_exposes_resources()
    print("\n=== All MCP Profile Tests Passed ===\n")
