"""CLI: doctor, registry inspection, profiles."""

import io
import os
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.cli import client as C
from nexhunter.cli import doctor
from nexhunter.core.availability import _parse_version, check_binary, detect_version


def _run(argv) -> tuple:
    """Run a CLI command, returning (exit_code, stdout)."""
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = C.main(argv)
    return code, buffer.getvalue()


# --------------------------------------------------------------------------
# Version detection
# --------------------------------------------------------------------------


def test_version_parsing():
    """Version strings are parsed out of real-world tool output."""
    print("[TEST] Version parsing...")
    cases = {
        "Nmap version 7.80 ( https://nmap.org )": "7.80",
        "curl 8.12.1 (Windows) libcurl/8.12.1": "8.12.1",
        "ffuf version: v2.1.0": "2.1.0",
        "clientVersion:\n  gitVersion: v1.29.0\n  buildDate: 2024-36.1": "1.29.0",
        "gobuster version 3.6.0": "3.6.0",
    }
    for output, expected in cases.items():
        assert _parse_version(output) == expected, (
            f"{output!r} parsed as {_parse_version(output)!r}, expected {expected!r}"
        )
    print(f"  [OK] {len(cases)} version strings parsed")


def test_ip_address_is_not_a_version():
    """An IP address in the output is not mistaken for a version number."""
    print("[TEST] IP addresses rejected as versions...")
    # nslookup prints the resolver address, which looks like a dotted version.
    assert _parse_version("Default Server: router\nAddress: 192.168.0.1") is None
    assert _parse_version("Server: 8.8.8.8") is None
    # A real version alongside an IP still parses.
    assert _parse_version("tool 2.1.0 talking to 10.0.0.1") == "2.1.0"
    print("  [OK] IPs not read as versions")


def test_missing_binary_reported_not_raised():
    """Probing an absent binary reports it rather than raising."""
    print("[TEST] Missing binary handled...")
    status = check_binary("nexhunter-definitely-not-installed")

    assert not status.installed
    assert status.version is None
    assert status.error
    assert detect_version("nexhunter-definitely-not-installed") is None
    print("  [OK] Missing binary reported cleanly")


def test_python_binary_is_detected():
    """A binary that certainly exists is detected with a version."""
    print("[TEST] Present binary detected...")
    name = Path(sys.executable).stem  # "python" or "python3"
    status = check_binary(name)

    if not status.installed:
        print(f"  [SKIP] {name} not on PATH in this environment")
        return

    assert status.path, "an installed binary should report its path"
    assert status.version, f"expected a version for {name}"
    print(f"  [OK] {name} {status.version}")


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------


class _Env:
    """Set environment variables for the duration of a block, then restore."""

    def __init__(self, **values):
        self.values = values
        self.previous = {}

    def __enter__(self):
        for key, value in self.values.items():
            self.previous[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return self

    def __exit__(self, *exc):
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _doctor(**env) -> tuple:
    """Run doctor under a temporary environment, returning (code, output)."""
    buffer = io.StringIO()
    with _Env(**env), redirect_stdout(buffer):
        code = doctor.run(check_versions=False)
    return code, buffer.getvalue()


def test_doctor_runs_and_reports(tmp: Path):
    """doctor produces a full report and exits cleanly on a working install."""
    print("[TEST] doctor runs...")
    code, output = _doctor(
        NEXHUNTER_DATA_DIR=str(tmp),
    )

    assert code == 0, f"doctor reported failures on a working install:\n{output}"
    for section in ["NexHunter Doctor", "Core", "Security", "Stable tools"]:
        assert section in output, f"missing section {section!r}"
    assert "Process execution works" in output
    assert "Raw command execution disabled" in output
    print("  [OK] doctor reported all sections")


def test_doctor_reports_tool_maturity(tmp: Path):
    """doctor still reports installed binaries and flags destructive tools."""
    print("[TEST] doctor reports tools...")
    code, output = _doctor(
        NEXHUNTER_DATA_DIR=str(tmp),
    )
    assert code == 0, f"doctor should pass on a working install:\n{output}"
    assert "Destructive tools disabled" in output
    print("  [OK] Tool availability and risk flags reported")


def test_doctor_flags_missing_api_dependency(tmp: Path):
    """A missing flask must surface in doctor, but not fail the whole report:
    flask is the opt-in `[api]` extra (pyproject.toml), not a base dependency
    -- the minimal install (CLI, registry, execution layer) is supported
    without it by design.

    Regression: setup scripts installed only [mcp,browser], the server failed
    right after a "successful" setup, and doctor did not notice. Doctor must
    still surface the gap (WARN) even though it isn't a broken install (FAIL).
    """
    from unittest import mock

    print("[TEST] doctor flags missing flask...")
    real_import = __import__

    def no_flask(name, *args, **kwargs):
        if name == "flask":
            raise ImportError("No module named 'flask'")
        return real_import(name, *args, **kwargs)

    buffer = io.StringIO()
    with _Env(NEXHUNTER_DATA_DIR=str(tmp)), mock.patch("builtins.__import__", no_flask), redirect_stdout(buffer):
        code = doctor.run(check_versions=False)
    assert "flask not installed (API server unavailable)" in buffer.getvalue()
    assert code == 0, "a missing opt-in extra is a capability gap, not a broken install"
    print("  [OK] missing flask detected and reported, doesn't fail the minimal install")
    assert "defusedxml not installed" not in buffer.getvalue(), "unrelated deps must stay imported"


# --------------------------------------------------------------------------
# registry / profiles
# --------------------------------------------------------------------------


def test_registry_list_and_filter():
    """registry list works and honors filters."""
    print("[TEST] registry list...")
    code, output = _run(["registry", "list"])
    assert code == 0
    assert "nmap_scan" in output

    code, filtered = _run(["registry", "list", "--category", "recon"])
    assert code == 0
    assert "nmap_scan" in filtered
    assert "semgrep" not in filtered, "a code tool should not appear under recon"
    print("  [OK] registry list filters by category")


def test_registry_info():
    """registry info describes a tool, and rejects unknown names."""
    print("[TEST] registry info...")
    code, output = _run(["registry", "info", "nmap_scan"])
    assert code == 0
    assert "nmap_scan" in output
    assert "risk" in output
    assert "parameters" in output

    code, _ = _run(["registry", "info", "not_a_real_tool"])
    assert code == 1, "unknown tool should exit non-zero"
    print("  [OK] registry info works and rejects unknown tools")


def test_profiles_command():
    """profiles lists all profiles, and can show one."""
    print("[TEST] profiles command...")
    code, output = _run(["profiles"])
    assert code == 0
    assert "nexhunter-core" in output
    assert "nexhunter-web" in output

    code, single = _run(["profiles", "--name", "nexhunter-recon"])
    assert code == 0
    assert "subfinder_enum" in single

    code, _ = _run(["profiles", "--name", "nope"])
    assert code == 1, "unknown profile should exit non-zero"
    print("  [OK] profiles listed and filtered")


if __name__ == "__main__":
    print("\n=== CLI / Availability Tests ===\n")
    test_version_parsing()
    test_ip_address_is_not_a_version()
    test_missing_binary_reported_not_raised()
    test_python_binary_is_detected()
    with tempfile.TemporaryDirectory() as raw:
        test_doctor_runs_and_reports(Path(raw))
    with tempfile.TemporaryDirectory() as raw:
        test_doctor_reports_tool_maturity(Path(raw))
    with tempfile.TemporaryDirectory() as raw:
        test_doctor_flags_missing_api_dependency(Path(raw))
    test_registry_list_and_filter()
    test_registry_info()
    test_profiles_command()
    print("\n=== All CLI / Availability Tests Passed ===\n")
