"""`nexhunter doctor` - check that this installation can actually run.

Reports what is true about the current environment. By default it changes
nothing: the point is to tell an operator what will and will not work. The
opt-in ``--install`` flag is the one exception -- it runs the known install
recipe (apt/go/pipx) for each missing tool, after showing the plan and asking
for confirmation. Without ``--install`` no binary is ever touched.
"""

import os
import platform
import subprocess
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
    for module, purpose in (
        ("fastmcp", "MCP server"),
        ("flask", "API server"),
        ("defusedxml", "safe XML parsing"),
    ):
        try:
            __import__(module)
            results.append((OK, f"{module} available ({purpose})"))
        except ImportError:
            # Python dependencies are part of the install, unlike optional tool
            # binaries: a missing one means the server or bridge cannot start.
            results.append((FAIL, f"{module} not installed ({purpose} unavailable)"))
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


def _install_missing(missing: list[tuple[str, str]], assume_yes: bool, dry_run: bool) -> None:
    """Install missing binaries via their known recipes (used by --install).

    ``missing`` is a list of (tool_name, binary). Shows the plan first, asks to
    confirm (unless assume_yes), then runs each recipe and re-checks the binary.
    A tool with no recipe, or whose installer (apt/go/pipx) is not on PATH, is
    reported and skipped -- never guessed at.
    """
    from nexhunter.cli import installer as I

    planned: list = []
    no_recipe: list[tuple[str, str]] = []
    for name, binary in missing:
        recipe = I.recipe_for(binary)
        (planned.append((name, binary, recipe)) if recipe else no_recipe.append((name, binary)))

    print("Install plan")
    for name, binary, recipe in planned:
        note = "" if I.method_available(recipe.method) else f"   ({recipe.method} NOT on PATH)"
        print(f"  {name} ({binary}): {I.command_str(recipe)}{note}")
    for name, binary in no_recipe:
        print(f"  {name} ({binary}): no known recipe -- install manually")
    if not planned:
        print("  Nothing installable: no known recipes for the missing tools.\n")
        return
    print()

    if dry_run:
        print("(dry run: nothing was installed)\n")
        return
    if not assume_yes:
        try:
            reply = input(f"Install {len(planned)} tool(s) with the commands above? [y/N] ").strip().lower()
        except EOFError:
            reply = ""
        if reply not in {"y", "yes"}:
            print("Aborted; nothing installed.\n")
            return

    installed = failed = skipped = 0
    for name, binary, recipe in planned:
        if not I.method_available(recipe.method):
            print(f"  {MISSING} {name}: {recipe.method} not installed, skipped")
            skipped += 1
            continue
        if check_binary(binary, with_version=False).installed:  # a prior step may have provided it
            print(f"  {OK} {name}: already present")
            continue
        print(f"  $ {I.command_str(recipe)}")
        try:
            proc = subprocess.run(I.command_for(recipe), check=False)  # noqa: S603 - argv from fixed recipe table
            if proc.returncode == 0 and check_binary(binary, with_version=False).installed:
                print(f"  {OK} {name} installed")
                installed += 1
            else:
                print(f"  {FAIL} {name}: exit {proc.returncode}")
                failed += 1
        except Exception as exc:  # noqa: BLE001 - reported per tool, loop continues
            print(f"  {FAIL} {name}: {exc}")
            failed += 1
    print(f"\nInstalled {installed}, failed {failed}, skipped {skipped}.\n")


def run(
    check_versions: bool = True,
    show_all_tools: bool = False,
    do_install: bool = False,
    assume_yes: bool = False,
    dry_run: bool = False,
) -> int:
    """Print the report. Returns a process exit code: 0 unless something failed.

    With ``do_install`` the missing stable tools that have a known recipe are
    installed after the report (see :func:`_install_missing`).
    """
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
    missing_specs: list[tuple[str, str]] = []  # (name, binary) for --install
    for spec in sorted(stable_specs, key=lambda s: s.name):
        status = check_binary(spec.binary, with_version=check_versions)
        if status.installed:
            installed_count += 1
            version = f" {status.version}" if status.version else ""
            tool_rows.append((OK, f"{spec.name} ({spec.binary}{version})"))
        else:
            missing_specs.append((spec.name, spec.binary))
            if show_all_tools:
                tool_rows.append((MISSING, f"{spec.name} ({spec.binary})"))
    if not show_all_tools and missing_specs:
        tool_rows.append((MISSING, f"{len(missing_specs)} other stable tools not installed (--all to list)"))
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

    if do_install:
        _install_missing(missing_specs, assume_yes=assume_yes, dry_run=dry_run)
    elif missing_specs:
        from nexhunter.cli import installer as I

        installable = sum(1 for _, binary in missing_specs if I.recipe_for(binary))
        if installable:
            print(f"{installable} of the missing stable tools have a known recipe -- "
                  f"run 'doctor --install' to install them.\n")

    if failures:
        print(f"{failures} failure(s), {warnings} warning(s). NexHunter will not run correctly.\n")
        return 1
    print(f"No failures, {warnings} warning(s).\n")
    return 0
