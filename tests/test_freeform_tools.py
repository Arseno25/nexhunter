"""Free-form execution tools: the sanctioned, contained HexStrike-style path.

execute_command and execute_python_script take an entire payload string and
execute it -- the capability HexStrike exposes through its raw /api/command,
kept inside the registry where it is typed, gated (intrusive), recorded,
uncacheable, and withheld from autonomous runs. There is no shell flag
anywhere: execute_command is just a builder that returns a ShellCommand instead
of an argv list, and the runner honors that contract. Every MCP profile
surfaces both tools, since they serve any engagement.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.api import mcp_profiles
from nexhunter.core import params as P
from nexhunter.core import tools as T
from nexhunter.core.tools import ShellCommand
from nexhunter.execution.service import ExecutionService

FREEFORM = {"execute_command", "execute_python_script"}


def test_freeform_tools_are_registered_and_gated():
    for name in FREEFORM:
        spec = T.get_tool_spec(name)
        assert spec is not None, f"{name} should be registered"
        assert spec.risk_level == "intrusive", f"{name} must be intrusive"
        assert spec.category == "utility", f"{name} must be utility category"
        assert not spec.cacheable, f"{name} must not be cached"
        assert spec.available, f"{name} must always be available (runs in-process)"

    shell = T.get_tool_spec("execute_command")
    assert isinstance(shell.build_cmd({"command": "echo hi"}), ShellCommand)
    python = T.get_tool_spec("execute_python_script")
    assert isinstance(python.build_cmd({"script": "print(1)"}), list)


def test_only_sanctioned_builders_emit_shell_commands():
    """Exactly one builder returns a ShellCommand; every other tool is argv."""
    probe = "alpha beta --flag; rm -rf /"
    shell_builders = []
    for name, spec in T.TOOLS.items():
        params = {key: (probe if default is None else default) for key, default in spec.params.items()}
        try:
            built = spec.build_cmd(params)
        except Exception:  # noqa: S112 - a builder that refuses the probe is skipped
            continue
        if built is None:
            continue
        if isinstance(built, ShellCommand):
            shell_builders.append(name)
    assert shell_builders == ["execute_command"], f"ShellCommand emitted by: {shell_builders}"


def test_every_profile_includes_freeform():
    """Freeform serves any engagement: all profiles surface the two tools."""
    for profile in mcp_profiles.PROFILES.values():
        exposed = set(mcp_profiles.tools_for(profile))
        assert FREEFORM <= exposed, f"{profile.name} missing freeform tools"


def test_profile_can_opt_out_of_freeform():
    strict = mcp_profiles.Profile(
        name="strict", description="scoped", categories=("recon",),
        include_freeform_tools=False,
    )
    exposed = set(mcp_profiles.tools_for(strict))
    assert exposed, "the strict profile should still expose its own tools"
    assert not (FREEFORM & exposed), f"freeform leaked into an opted-out profile: {FREEFORM & exposed}"


def test_text_params_allow_newlines_but_reject_null():
    spec = P.ParamSpec(name="script", type=P.ParamType.TEXT, required=True)
    assert spec.validate("line1\nline2\tprint(1)") == "line1\nline2\tprint(1)"
    try:
        spec.validate("bad\x00byte")
    except P.ValidationError:
        pass
    else:
        raise AssertionError("null byte must be rejected in TEXT params")


def test_execute_command_executes_through_the_shell():
    service = ExecutionService()
    result = service.run_direct("execute_command", {"command": "echo a && echo b"})
    assert result["ok"], result
    assert "a" in result["output"], result
    assert "b" in result["output"], result
    assert result["cached"] is False


def test_execute_command_is_recorded_on_the_tracked_path():
    service = ExecutionService()
    result = service.execute(
        "execute_command", {"command": "echo tracked"}, direct=False
    )
    assert result["ok"], result
    assert "tracked" in result["output"], result
    assert result.get("execution_id"), "tracked run must mint a record"


def test_execute_python_script_executes():
    service = ExecutionService()
    result = service.run_direct("execute_python_script", {"script": "print(2 + 2)"})
    assert result["ok"], result
    assert "4" in result["output"], result


def test_execute_python_script_accepts_multiline_code():
    service = ExecutionService()
    code = "for i in range(3):\n    print(i)"
    result = service.run_direct("execute_python_script", {"script": code})
    assert result["ok"], result
    for line in ("0", "1", "2"):
        assert line in result["output"], result


def test_missing_required_param_rejected():
    service = ExecutionService()
    result = service.run_direct("execute_command", {})
    assert not result["ok"]
    assert result["code"] == "INVALID_PARAMS", result


if __name__ == "__main__":
    print("\n=== Free-form Execution Tool Tests ===\n")
    test_freeform_tools_are_registered_and_gated()
    test_only_sanctioned_builders_emit_shell_commands()
    test_every_profile_includes_freeform()
    test_profile_can_opt_out_of_freeform()
    test_text_params_allow_newlines_but_reject_null()
    test_execute_command_executes_through_the_shell()
    test_execute_command_is_recorded_on_the_tracked_path()
    test_execute_python_script_executes()
    test_execute_python_script_accepts_multiline_code()
    test_missing_required_param_rejected()
    print("\n=== All Free-form Tests Passed ===\n")
