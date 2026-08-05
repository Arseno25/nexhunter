"""Free-form execution tools: the sanctioned, contained HexStrike-style path.

shell_command and python_script take an entire payload string and execute it
-- the capability HexStrike exposes through its raw /api/command, kept inside
the registry where it is typed, gated (intrusive), recorded, uncacheable, and
withheld from autonomous runs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.api import mcp_profiles
from nexhunter.core import params as P
from nexhunter.core import tools as T
from nexhunter.execution.service import ExecutionService

FREEFORM = {"shell_command", "python_script"}


def test_freeform_tools_are_registered_and_gated():
    for name in FREEFORM:
        spec = T.get_tool_spec(name)
        assert spec is not None, f"{name} should be registered"
        assert spec.risk_level == "intrusive", f"{name} must be intrusive"
        assert spec.category == "utility", f"{name} must be utility category"
        assert not spec.cacheable, f"{name} must not be cached"
        assert spec.available, f"{name} must always be available (runs in-process)"

    assert T.get_tool_spec("shell_command").shell is True
    assert T.get_tool_spec("python_script").shell is False


def test_only_sanctioned_tools_use_shell():
    offenders = [name for name, spec in T.TOOLS.items() if spec.shell]
    assert set(offenders) == {"shell_command"}, f"shell flag on: {offenders}"


def test_freeform_profile_exposes_exactly_the_two_tools():
    profile = mcp_profiles.get_profile("nexhunter-freeform")
    exposed = set(mcp_profiles.tools_for(profile))
    assert exposed == FREEFORM, f"freeform profile exposes: {exposed}"


def test_default_profile_includes_freeform():
    profile = mcp_profiles.get_profile("nexhunter-full")
    assert FREEFORM <= set(mcp_profiles.tools_for(profile))


def test_text_params_allow_newlines_but_reject_null():
    spec = P.ParamSpec(name="code", type=P.ParamType.TEXT, required=True)
    assert spec.validate("line1\nline2\tprint(1)") == "line1\nline2\tprint(1)"
    try:
        spec.validate("bad\x00byte")
    except P.ValidationError:
        pass
    else:
        raise AssertionError("null byte must be rejected in TEXT params")


def test_shell_command_executes_through_the_shell():
    service = ExecutionService()
    result = service.run_direct("shell_command", {"command": "echo a && echo b"})
    assert result["ok"], result
    assert "a" in result["output"], result
    assert "b" in result["output"], result
    assert result["cached"] is False


def test_shell_command_is_recorded_on_the_tracked_path():
    service = ExecutionService()
    result = service.execute(
        "shell_command", {"command": "echo tracked"}, direct=False
    )
    assert result["ok"], result
    assert "tracked" in result["output"], result
    assert result.get("execution_id"), "tracked run must mint a record"


def test_python_script_executes():
    service = ExecutionService()
    result = service.run_direct("python_script", {"code": "print(2 + 2)"})
    assert result["ok"], result
    assert "4" in result["output"], result


def test_python_script_accepts_multiline_code():
    service = ExecutionService()
    code = "for i in range(3):\n    print(i)"
    result = service.run_direct("python_script", {"code": code})
    assert result["ok"], result
    for line in ("0", "1", "2"):
        assert line in result["output"], result


def test_missing_required_param_rejected():
    service = ExecutionService()
    result = service.run_direct("shell_command", {})
    assert not result["ok"]
    assert result["code"] == "INVALID_PARAMS", result


if __name__ == "__main__":
    print("\n=== Free-form Execution Tool Tests ===\n")
    test_freeform_tools_are_registered_and_gated()
    test_only_sanctioned_tools_use_shell()
    test_freeform_profile_exposes_exactly_the_two_tools()
    test_default_profile_includes_freeform()
    test_text_params_allow_newlines_but_reject_null()
    test_shell_command_executes_through_the_shell()
    test_shell_command_is_recorded_on_the_tracked_path()
    test_python_script_executes()
    test_python_script_accepts_multiline_code()
    test_missing_required_param_rejected()
    print("\n=== All Free-form Tests Passed ===\n")
