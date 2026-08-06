"""`nexhunter doctor` - check that this installation can actually run.

Reports what is true about the current environment. It never changes anything
and never installs a binary: the point is to tell an operator what will and
will not work, not to fix it for them.
"""

import os
import platform
import sys
from pathlib import Path

from nexhunter.core import tools as T
from nexhunter.core.availability import check_binary
from nexhunter.execution.workspace import data_dir

OK = "[OK]"
WARN = "[WARN]"
MISSING = "[MISSING]"
FAIL = "[FAIL]"

MIN_PYTHON = (3, 10)


def _check_python() -> tuple[str, str]:
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info[:2] < MIN_PYTHON:
        return FAIL, f"Python {version} (needs {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+)"
    return OK, f"Python {version}"


def _check_platform() -> tuple[str, str]:
    system = platform.system()
    if system in ("Linux", "Darwin", "Windows"):
        return OK, f"{system} {platform.release()}"
    return WARN, f"{system} (untested platform)"


def _check_data_dir() -> tuple[str, str]:
    directory = data_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / ".nexhunter-write-probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return OK, f"Data directory writable: {directory}"
    except OSError as exc:
        return FAIL, f"Data directory not writable: {directory} ({exc})"


def _check_binding() -> tuple[str, str]:
    host = os.environ.get("NEXHUNTER_BIND_HOST", "127.0.0.1").strip()
    external_allowed = os.environ.get("NEXHUNTER_EXTERNAL_BIND_ALLOWED", "").lower() in {"1", "true", "yes", "on"}

    if host in ("127.0.0.1", "localhost", "::1"):
        return OK, f"Server binds to loopback ({host})"
    if external_allowed:
        return WARN, f"Server binds to {host} with external binding explicitly allowed"
    return FAIL, f"Server binds to {host} but NEXHUNTER_EXTERNAL_BIND_ALLOWED is not set"


def _check_destructive_flags() -> list[tuple[str, str]]:
    results = []
    for variable, label in (
        ("NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED", "Destructive tools"),
        ("NEXHUNTER_INTRUSIVE_TOOLS_ENABLED", "Intrusive tools"),
    ):
        enabled = os.environ.get(variable, "").lower() in {"1", "true", "yes", "on"}
        results.append((WARN if enabled else OK, f"{label} {'ENABLED' if enabled else 'disabled'}"))
    return results


def _check_dependencies() -> list[tuple[str, str]]:
    results = []
    for module, purpose in (("fastmcp", "MCP server"), ("defusedxml", "safe XML parsing")):
        try:
            __import__(module)
            results.append((OK, f"{module} available ({purpose})"))
        except ImportError:
            results.append((MISSING, f"{module} not installed ({purpose} unavailable)"))
    return results


def _check_browser_engine() -> tuple[str, str]:
    """Report whether browser_crawl can drive a real headless browser."""
    import importlib.util

    has_selenium = importlib.util.find_spec("selenium") is not None
    chrome = next((b for b in T._CHROME_BINARIES if T.which(b)), None)
    if has_selenium and chrome:
        return OK, f"Browser engine ready (selenium + {chrome})"
    missing = []
    if not has_selenium:
        missing.append("selenium (pip install nexhunter[browser])")
    if not chrome:
        missing.append("a Chrome/Chromium binary")
    return WARN, f"browser_crawl falls back to static crawl, no JS: missing {', '.join(missing)}"


def _check_execution() -> tuple[str, str]:
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
    sections: list[tuple[str, list[tuple[str, str]]]] = []

    core = [
        _check_python(),
        _check_platform(),
        _check_data_dir(),
        _check_binding(),
    ]
    core.extend(_check_dependencies())
    core.append(_check_browser_engine())
    core.append(_check_execution())
    sections.append(("Core", core))

    security = [
        (OK, "Raw command execution disabled (registry tools only)"),
        (OK, "Shell execution only via the execute_command builder contract"),
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

    per_category: dict[str, list[int]] = {}
    for spec in T.TOOLS.values():
        bucket = per_category.setdefault(spec.category, [0, 0])
        bucket[1] += 1
        if spec.available:
            bucket[0] += 1
    registry_rows = []
    installed_total = sum(c[0] for c in per_category.values())
    for category, (installed, total) in sorted(per_category.items()):
        marker = OK if installed else MISSING
        registry_rows.append((marker, f"{category}: {installed}/{total} available"))
    sections.append((f"Registry availability ({installed_total}/{len(T.TOOLS)} tools on PATH)", registry_rows))

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
