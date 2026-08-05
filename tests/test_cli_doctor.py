"""CLI: doctor, registry inspection, profiles, engagement validation."""

import io
import json
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
        NEXHUNTER_ENFORCE="false",
        NEXHUNTER_ENGAGEMENT=None,
    )

    assert code == 0, f"doctor reported failures on a working install:\n{output}"
    for section in ["NexHunter Doctor", "Core", "Security", "Stable tools"]:
        assert section in output, f"missing section {section!r}"
    assert "Process execution works" in output
    assert "Raw command execution disabled" in output
    print("  [OK] doctor reported all sections")


def test_doctor_passes_with_an_active_engagement(tmp: Path):
    """Enforcement on plus a valid engagement is a healthy install."""
    print("[TEST] doctor passes with an engagement...")
    from datetime import datetime, timedelta

    from nexhunter.engagements.store import EngagementStore

    now = datetime.utcnow()
    EngagementStore(base_dir=tmp).create({
        "id": "ENG-DOCTOR",
        "name": "Doctor test",
        "status": "active",
        "starts_at": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "scope": {"allowed_targets": ["example.com"], "allowed_risk_levels": ["passive"]},
    })

    code, output = _doctor(
        NEXHUNTER_DATA_DIR=str(tmp),
        NEXHUNTER_ENFORCE="true",
        NEXHUNTER_ENGAGEMENT=None,
    )

    assert code == 0, f"expected a clean report with an active engagement:\n{output}"
    assert "Scope enforcement on" in output
    assert "ENG-DOCTOR" in output
    print("  [OK] Active engagement reported as healthy")


def test_doctor_warns_without_token(tmp: Path):
    """doctor warns when no API token is configured."""
    print("[TEST] doctor warns on missing token...")
    _, output = _doctor(
        NEXHUNTER_DATA_DIR=str(tmp),
        NEXHUNTER_ENFORCE="false",
        NEXHUNTER_API_TOKEN=None,
    )
    assert "API token not configured" in output
    print("  [OK] Missing token warned")


def test_doctor_fails_on_a_fresh_enforcing_install(tmp: Path):
    """Enforcement on with no engagement is a failure, not a warning.

    That combination denies every execution, so it has to be loud -- and the
    message has to say how to fix it, since this is what a fresh install looks
    like now that enforcement is the default.
    """
    print("[TEST] doctor fails on a fresh enforcing install...")
    code, output = _doctor(
        NEXHUNTER_DATA_DIR=str(tmp),
        NEXHUNTER_ENFORCE="true",
        NEXHUNTER_ENGAGEMENT=None,
    )

    assert code == 1, f"expected a non-zero exit with no engagement:\n{output}"
    assert "No active engagement" in output
    assert "nexhunter engagement create" in output, "the failure should say how to fix it"
    print("  [OK] Reported as a failure, with the fix")


def test_doctor_flags_a_missing_engagement_file(tmp: Path):
    """A NEXHUNTER_ENGAGEMENT pointing at nothing is reported."""
    print("[TEST] doctor flags a missing engagement file...")
    code, output = _doctor(
        NEXHUNTER_DATA_DIR=str(tmp),
        NEXHUNTER_ENFORCE="true",
        NEXHUNTER_ENGAGEMENT=str(tmp / "does-not-exist.json"),
    )

    assert code == 1
    assert "missing file" in output
    print("  [OK] Missing engagement file reported")


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


# --------------------------------------------------------------------------
# engagement validation
# --------------------------------------------------------------------------

def _write_engagement(directory: Path, **overrides) -> Path:
    payload = {
        "id": "ENG-2026-001",
        "name": "Example Assessment",
        "status": "active",
        "starts_at": "2026-01-01T00:00:00",
        "expires_at": "2030-01-01T00:00:00",
        "scope": {
            "allowed_targets": ["example.com", "*.example.com"],
            "denied_targets": ["admin.example.com"],
            "allowed_risk_levels": ["passive", "active"],
        },
    }
    payload.update(overrides)
    path = directory / "engagement.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_engagement_validate_accepts_valid_file(tmp: Path):
    """A well-formed engagement validates."""
    print("[TEST] engagement validate accepts a valid file...")
    path = _write_engagement(tmp)
    code, output = _run(["engagement", "validate", str(path)])

    assert code == 0, f"expected a valid engagement to pass:\n{output}"
    assert "ENG-2026-001" in output
    assert "[OK]" in output
    print("  [OK] Valid engagement accepted")


def test_engagement_validate_rejects_empty_allowlist(tmp: Path):
    """An empty allow-list is a failure: it denies everything."""
    print("[TEST] engagement validate rejects an empty allow-list...")
    path = _write_engagement(
        tmp,
        scope={"allowed_targets": [], "denied_targets": [], "allowed_risk_levels": ["passive"]},
    )
    code, output = _run(["engagement", "validate", str(path)])

    assert code == 1, "an empty allow-list must not validate"
    assert "empty" in output.lower()
    print("  [OK] Empty allow-list rejected")


def test_engagement_validate_rejects_missing_file(tmp: Path):
    """A missing file is reported, not raised."""
    print("[TEST] engagement validate rejects a missing file...")
    code, output = _run(["engagement", "validate", str(tmp / "nope.json")])

    assert code == 1
    assert "Could not load" in output
    print("  [OK] Missing file reported")


if __name__ == "__main__":
    print("\n=== CLI / Availability Tests ===\n")
    test_version_parsing()
    test_ip_address_is_not_a_version()
    test_missing_binary_reported_not_raised()
    test_python_binary_is_detected()
    with tempfile.TemporaryDirectory() as raw:
        test_doctor_runs_and_reports(Path(raw))
    with tempfile.TemporaryDirectory() as raw:
        test_doctor_passes_with_an_active_engagement(Path(raw))
    with tempfile.TemporaryDirectory() as raw:
        test_doctor_warns_without_token(Path(raw))
    with tempfile.TemporaryDirectory() as raw:
        test_doctor_fails_on_a_fresh_enforcing_install(Path(raw))
    with tempfile.TemporaryDirectory() as raw:
        test_doctor_flags_a_missing_engagement_file(Path(raw))
    test_registry_list_and_filter()
    test_registry_info()
    test_profiles_command()
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        test_engagement_validate_accepts_valid_file(tmp)
        test_engagement_validate_rejects_empty_allowlist(tmp)
        test_engagement_validate_rejects_missing_file(tmp)
    print("\n=== All CLI / Availability Tests Passed ===\n")
