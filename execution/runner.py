"""Process execution with tree termination, timeouts, and output limits.

Two things this fixes over a plain subprocess.run(timeout=...):

  * Child cleanup. subprocess kills only the process it spawned. Security
    tools routinely fork helpers, so a timeout used to leave grandchildren
    scanning a target after the request was abandoned. Processes are started
    in their own group/session and the whole group is signalled.

  * Graceful shutdown. Tools are given a termination signal and a grace
    period to flush partial output before being killed outright.

stdout and stderr are captured to separate files inside the execution's
workspace, which both avoids pipe-buffer deadlock on chatty tools and makes
the raw output an artifact rather than something held in memory.
"""

import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

DEFAULT_MAX_OUTPUT_BYTES = 10 * 1024 * 1024
DEFAULT_GRACE_SECONDS = 5.0
_POLL_INTERVAL = 0.05

STDOUT_NAME = "stdout.log"
STDERR_NAME = "stderr.log"

_IS_WINDOWS = os.name == "nt"


@dataclass
class RunResult:
    """Outcome of one process run."""

    exit_code: Optional[int]
    timed_out: bool = False
    terminated: bool = False
    truncated: bool = False
    error: Optional[str] = None
    error_code: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    pid: Optional[int] = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.terminated and not self.error


def _spawn_kwargs() -> dict:
    """Platform flags that put the child in its own killable group."""
    if _IS_WINDOWS:
        return {
            "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW,
        }
    return {"start_new_session": True}


def terminate_tree(proc: subprocess.Popen, grace: float = DEFAULT_GRACE_SECONDS) -> None:
    """Stop a process and everything it spawned.

    Signals the whole group, waits out the grace period, then kills what is
    left. Safe to call on an already-dead process.
    """
    if proc.poll() is not None:
        return

    if _IS_WINDOWS:
        # Ask the whole group to stop first. The child was started with
        # CREATE_NEW_PROCESS_GROUP, so a break reaches its descendants too.
        try:
            os.kill(proc.pid, signal.CTRL_BREAK_EVENT)
        except (OSError, ValueError, AttributeError):
            pass
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            pass

        # Sweep the tree unconditionally. Killing only the direct child
        # orphans whatever it spawned, and an orphaned scanner keeps running
        # against the target long after the request was abandoned.
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            capture_output=True,
            check=False,
        )
    else:
        try:
            group = os.getpgid(proc.pid)
        except (ProcessLookupError, OSError):
            group = None

        if group is not None:
            try:
                os.killpg(group, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            try:
                proc.wait(timeout=grace)
                return
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(group, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass

    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass


def _read_capped(path: Path, limit: int) -> str:
    if not path.exists():
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read(limit)


class ProcessRunner:
    """Run tool commands under a timeout, an output cap, and tree cleanup."""

    def __init__(
        self,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        grace_seconds: float = DEFAULT_GRACE_SECONDS,
    ):
        self.max_output_bytes = max_output_bytes
        self.grace_seconds = grace_seconds

    def run(
        self,
        cmd: List[str],
        timeout: int,
        workdir: Path,
        cancel: Optional[callable] = None,
    ) -> RunResult:
        """Execute cmd, writing output into workdir.

        cmd must be an argument list; there is no shell involved anywhere in
        this path. `cancel` is polled to support external termination.
        """
        if not cmd:
            return RunResult(exit_code=None, error="empty command", error_code="EMPTY_COMMAND")

        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        stdout_path = workdir / STDOUT_NAME
        stderr_path = workdir / STDERR_NAME

        try:
            with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
                proc = subprocess.Popen(
                    cmd,
                    stdout=out,
                    stderr=err,
                    stdin=subprocess.DEVNULL,
                    cwd=str(workdir),
                    **_spawn_kwargs(),
                )
                result = self._supervise(proc, timeout, stdout_path, stderr_path, cancel)
        except FileNotFoundError:
            return RunResult(
                exit_code=None,
                error=f"binary '{cmd[0]}' not found on PATH",
                error_code="BINARY_NOT_FOUND",
            )
        except PermissionError as exc:
            return RunResult(exit_code=None, error=str(exc), error_code="PERMISSION_DENIED")

        result.stdout = _read_capped(stdout_path, self.max_output_bytes)
        result.stderr = _read_capped(stderr_path, self.max_output_bytes)
        result.stdout_bytes = stdout_path.stat().st_size if stdout_path.exists() else 0
        result.stderr_bytes = stderr_path.stat().st_size if stderr_path.exists() else 0
        return result

    def _supervise(
        self,
        proc: subprocess.Popen,
        timeout: int,
        stdout_path: Path,
        stderr_path: Path,
        cancel: Optional[callable],
    ) -> RunResult:
        """Wait for the process, enforcing timeout, cancellation, output cap."""
        deadline = time.monotonic() + timeout

        while True:
            exit_code = proc.poll()
            if exit_code is not None:
                return RunResult(exit_code=exit_code, pid=proc.pid)

            if cancel is not None and cancel():
                terminate_tree(proc, self.grace_seconds)
                return RunResult(
                    exit_code=proc.poll(),
                    terminated=True,
                    error="terminated by request",
                    error_code="TERMINATED",
                    pid=proc.pid,
                )

            if time.monotonic() >= deadline:
                terminate_tree(proc, self.grace_seconds)
                return RunResult(
                    exit_code=proc.poll(),
                    timed_out=True,
                    error=f"timed out after {timeout}s",
                    error_code="TIMEOUT",
                    pid=proc.pid,
                )

            if self._output_exceeded(stdout_path, stderr_path):
                terminate_tree(proc, self.grace_seconds)
                return RunResult(
                    exit_code=proc.poll(),
                    terminated=True,
                    truncated=True,
                    error=f"output exceeded {self.max_output_bytes} bytes",
                    error_code="OUTPUT_LIMIT",
                    pid=proc.pid,
                )

            time.sleep(_POLL_INTERVAL)

    def _output_exceeded(self, stdout_path: Path, stderr_path: Path) -> bool:
        total = 0
        for path in (stdout_path, stderr_path):
            try:
                total += path.stat().st_size
            except OSError:
                continue
        return total > self.max_output_bytes
