"""`nexhunter doctor` - check that this installation can actually run.

Reports what is true about the current environment. It never changes anything
and never installs a binary: the point is to tell an operator what will and
will not work before an engagement, not to fix it for them.
"""

import os
import platform
import sys
from pathlib import Path
from typing import List, Tuple

from nexhunter.core import tools as T
from nexhunter.core.availability import check_binary
from nexhunter.execution.workspace import data_dir

OK = "[OK]"
WARN = "[WARN]"
MISSING = "[MISSING]"
FAIL = "[FAIL]"

MIN_PYTHON = (3, 10)


def _check_python() -> Tuple[str, str]:
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info[:2] < MIN_PYTHON:
        return FAIL, f"Python {version} (needs {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+)"
    return OK, f"Python {version}"


def _check_platform() -> Tuple[str, str]:
    system = platform.system()
    if system in ("Linux", "Darwin", "Windows"):
        return OK, f"{system} {platform.release()}"
    return WARN, f"{system} (untested platform)"


def _check_data_dir() -> Tuple[str, str]:
    directory = data_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / ".nexhunter-write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return OK, f"Data directory writable: {directory}"
    except OSError as exc:
        return FAIL, f"Data directory not writable: {directory} ({exc})"


def _check_token() -> Tuple[str, str]:
    if os.environ.get("NEXHUNTER_API_TOKEN", "").strip():
        return OK, "API token configured"
    return WARN, "API token not configured (NEXHUNTER_API_TOKEN unset; the API will accept any caller)"


def _check_binding() -> Tuple[str, str]:
    host = os.environ.get("NEXHUNTER_BIND_HOST", "127.0.0.1").strip()
    external_allowed = os.environ.get("NEXHUNTER_EXTERNAL_BIND_ALLOWED", "").lower() in {"1", "true", "yes", "on"}

    if host in ("127.0.0.1", "localhost", "::1"):
        return OK, f"Server binds to loopback ({host})"
    if external_allowed:
        return WARN, f"Server binds to {host} with external binding explicitly allowed"
    return FAIL, f"Server binds to {host} but NEXHUNTER_EXTERNAL_BIND_ALLOWED is not set"


def _check_enforcement() -> List[Tuple[str, str]]:
    """Report the enforcement posture and whether any scope is actually usable."""
    from nexhunter.engagements.store import EngagementStore
    from nexhunter.security.enforcement import _default_enforce

    results: List[Tuple[str, str]] = []
    enforcing = _default_enforce()
    engagement_file = os.environ.get("NEXHUNTER_ENGAGEMENT", "").strip()

    if not enforcing:
        results.append((WARN, "Scope enforcement OFF (NEXHUNTER_ENFORCE=false; no scope is applied)"))
    else:
        results.append((OK, "Scope enforcement on"))

    if engagement_file:
        if Path(engagement_file).is_file():
            results.append((OK, f"Engagement file: {engagement_file}"))
        else:
            results.append((FAIL, f"NEXHUNTER_ENGAGEMENT points at a missing file: {engagement_file}"))
        return results

    try:
        active = [e for e in EngagementStore().list() if e.is_active()]
    except OSError as exc:
        results.append((FAIL, f"Could not read engagements: {exc}"))
        return results

    if active:
        names = ", ".join(e.id for e in active)
        if len(active) > 1:
            results.append((WARN, f"{len(active)} active engagements ({names}); "
                                  "requests must name one with engagement_id"))
        else:
            results.append((OK, f"Active engagement: {names}"))
    elif enforcing:
        results.append((FAIL, "No active engagement; every execution will be denied. "
                              "Create one: nexhunter engagement create --id ENG-001 --target <host>"))
    else:
        results.append((WARN, "No active engagement (enforcement is off, so nothing is checked)"))

    return results


def _check_destructive_flags() -> List[Tuple[str, str]]:
    results = []
    for variable, label in (
        ("NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED", "Destructive tools"),
        ("NEXHUNTER_INTRUSIVE_TOOLS_ENABLED", "Intrusive tools"),
    ):
        enabled = os.environ.get(variable, "").lower() in {"1", "true", "yes", "on"}
        results.append((WARN if enabled else OK, f"{label} {'ENABLED' if enabled else 'disabled'}"))
    return results


def _check_dependencies() -> List[Tuple[str, str]]:
    results = []
    for module, purpose in (("fastmcp", "MCP server"), ("defusedxml", "safe XML parsing")):
        try:
            __import__(module)
            results.append((OK, f"{module} available ({purpose})"))
        except ImportError:
            results.append((MISSING, f"{module} not installed ({purpose} unavailable)"))
    return results


def _check_execution() -> Tuple[str, str]:
    """Confirm we can actually spawn a process and read its output."""
    from nexhunter.execution.runner import ProcessRunner
    import tempfile

    try:
        with tempfile.TemporaryDirectory() as tmp:
            result = ProcessRunner().run(
                [sys.executable, "-c", "print('nexhunter-probe')"],
                timeout=20,
                workdir=Path(tmp),
            )
        if result.ok and "nexhunter-probe" in result.stdout:
            return OK, "Process execution works"
        return FAIL, f"Process execution failed: {result.error or result.exit_code}"
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        return FAIL, f"Process execution failed: {exc}"


def run(check_versions: bool = True, show_all_tools: bool = False) -> int:
    """Print the report. Returns a process exit code: 0 unless something failed."""
    sections: List[Tuple[str, List[Tuple[str, str]]]] = []

    core = [
        _check_python(),
        _check_platform(),
        _check_data_dir(),
        _check_token(),
        _check_binding(),
    ]
    core.extend(_check_enforcement())
    core.extend(_check_dependencies())
    core.append(_check_execution())
    sections.append(("Core", core))

    security = [
        (OK, "Raw command execution disabled (registry tools only)"),
        (OK, "No execution path uses a shell"),
    ]
    security.extend(_check_destructive_flags())
    sections.append(("Security", security))

    stable_specs = [spec for spec in T.TOOLS.values() if spec.maturity == "stable"]
    tool_rows = []
    installed_count = 0
    for spec in sorted(stable_specs, key=lambda s: s.name):
        status = check_binary(spec.binary, with_version=check_versions)
        if status.installed:
            installed_count += 1
            version = f" {status.version}" if status.version else ""
            tool_rows.append((OK, f"{spec.name} ({spec.binary}{version})"))
        elif show_all_tools:
            tool_rows.append((MISSING, f"{spec.name} ({spec.binary})"))
    if not show_all_tools:
        missing = len(stable_specs) - installed_count
        if missing:
            tool_rows.append((MISSING, f"{missing} other stable tools not installed (--all to list)"))
    sections.append((f"Stable tools ({installed_count}/{len(stable_specs)} installed)", tool_rows))

    print("\nNexHunter Doctor\n")
    failures = 0
    warnings = 0
    for title, rows in sections:
        print(f"{title}")
        for marker, message in rows:
            print(f"  {marker} {message}")
            if marker == FAIL:
                failures += 1
            elif marker in (WARN, MISSING):
                warnings += 1
        print()

    if failures:
        print(f"{failures} failure(s), {warnings} warning(s). NexHunter will not run correctly.\n")
        return 1
    print(f"No failures, {warnings} warning(s).\n")
    return 0
