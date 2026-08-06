"""Legacy command execution helpers (ProcessRunner delegation, PATH lookup)."""

import shutil


_OUT_CAP = 2_000_000  # 2 MB cap on legacy-path output (primary path caps at 10 MB via ProcessRunner)


def run(cmd: list, timeout: int) -> dict:
    """Run one command for the legacy Engine path (probe, portscan, recon...).

    Delegates to execution/runner.ProcessRunner so this path gets the same
    process-tree cleanup on timeout as the primary MCP // /api/command path --
    a timed-out nmap no longer leaves grandchild helpers orphaned. Runs in a
    throwaway workdir and maps the RunResult back to the legacy dict contract.
    ProcessRunner is imported lazily to avoid an import cycle (execution imports
    core.tools).
    """
    import tempfile
    from pathlib import Path

    from nexhunter.execution.runner import ProcessRunner

    with tempfile.TemporaryDirectory(prefix="nexhunter-legacy-") as scratch:
        r = ProcessRunner().run(cmd, timeout=timeout, workdir=Path(scratch))

    error = r.error
    if r.timed_out and not error:
        error = f"timed out after {timeout}s"
    return {
        "ok": r.exit_code == 0 and not r.error and not r.timed_out and not r.terminated,
        "exit": r.exit_code if r.exit_code is not None else -1,
        "stdout": r.stdout[:_OUT_CAP],
        "stderr": r.stderr[:_OUT_CAP],
        "error": error,
    }


def which(bin_name: str) -> str | None:
    """Check if binary exists in PATH."""
    return shutil.which(bin_name)
