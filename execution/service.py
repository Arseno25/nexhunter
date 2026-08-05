"""The single execution path.

Both the REST API and the MCP server call `ExecutionService.execute()`. Neither
builds commands or spawns processes on its own -- that is what keeps the two
interfaces from drifting apart.

Order of operations:

    validate params -> build argv -> run -> record
"""

import logging
import os
import sys
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from nexhunter.core import tools as T
from nexhunter.execution.cache import ResultCache
from nexhunter.execution.models import ExecutionRecord, ExecutionStatus
from nexhunter.execution.registry import ExecutionRegistry
from nexhunter.execution.runner import ProcessRunner, RunResult
from nexhunter.execution.workspace import Workspace, WorkspaceError
from nexhunter.security.redaction import SecretRedactor

log = logging.getLogger("nexhunter.execution")

# Color the status token when writing to a real terminal (mirrors the server
# banner). NO_COLOR disables it; FORCE_COLOR forces it on.
_USE_COLOR = bool(os.environ.get("FORCE_COLOR")) or (
    not os.environ.get("NO_COLOR")
    and getattr(sys.stdout, "isatty", lambda: False)()
)
_STATUS_STYLE = {
    "RUNNING": ("\033[38;5;51m", "▶"),
    "COMPLETED": ("\033[38;5;46m", "✅"),
    "FAILED": ("\033[38;5;196m", "❌"),
    "TIMEOUT": ("\033[38;5;208m", "⏱"),
    "TERMINATED": ("\033[38;5;208m", "🛑"),
    "BLOCKED": ("\033[38;5;129m", "🚫"),
}


def _tool_line(status: str, tool: str, target: str = "", extra: str = "") -> str:
    """One-line, hexstrike-style tool event for the logs."""
    color, icon = _STATUS_STYLE.get(status, ("", "•"))
    token = f"{icon} {status:<10}"
    if _USE_COLOR and color:
        token = f"{color}{token}\033[0m"
    dest = f"  →  {target}" if target else ""
    tail = f"  {extra}" if extra else ""
    return f"{token} {tool}{dest}{tail}"


class ExecutionService:
    """Validate, build, run, and record one tool execution."""

    def __init__(
        self,
        registry: Optional[ExecutionRegistry] = None,
        runner: Optional[ProcessRunner] = None,
        redactor: Optional[SecretRedactor] = None,
        cache: Optional[ResultCache] = None,
    ):
        self.registry = registry or ExecutionRegistry()
        self.runner = runner or ProcessRunner()
        self.redactor = redactor or SecretRedactor()
        # Result cache for the one execution path. Only deterministic terminal
        # results are stored; see execution/cache.py.
        self.cache = cache or ResultCache.from_env()
        # Captured output per execution. Bounded and lock-guarded: the server
        # is threaded and this must not grow for the life of the process.
        self._outputs: "OrderedDict[str, tuple]" = OrderedDict()
        self._outputs_lock = threading.Lock()
        self._max_outputs = 200

    def execute(
        self,
        tool_name: str,
        params: Dict[str, Any],
        run_async: bool = False,
        no_cache: bool = False,
    ) -> Dict[str, Any]:
        """Run one registered tool. Returns an API-shaped result dict.

        A deterministic terminal result is served from the cache when the same
        tool and normalized parameters were run before. A cache hit returns the
        original execution's result (with ``cached: True``) and does not mint a
        new record, so the state machine is never asked for an illegal jump.
        """
        spec = T.get_tool_spec(tool_name)
        if spec is None:
            return _error("UNKNOWN_TOOL", f"unknown tool: {tool_name}")

        params = params or {}

        # Cache probe. Normalize once (pure, cheap) to build the key; on a valid
        # hit we return without touching the runner or the registry. On an
        # invalid or missing entry we fall through to the full path below, which
        # re-normalizes and produces the proper record and error.
        cache_key: Optional[str] = None
        if self.cache.enabled and spec.cacheable and not no_cache:
            probe_merged, probe_err = spec.normalize(params)
            if probe_err is None:
                cache_key = ResultCache.key_for(tool_name, probe_merged)
                cached = self.cache.get(cache_key)
                if cached is not None:
                    return {**cached.result, "cached": True}

        record = ExecutionRecord(
            tool_name=tool_name,
            risk_level=spec.risk_level,
            redacted_parameters=self.redactor.redact_dict(dict(params)),
        )
        self.registry.add(record)

        record.transition(ExecutionStatus.VALIDATING)
        merged, err = spec.normalize(params)
        if err is not None:
            return self._fail(record, "INVALID_PARAMS", err, blocked=True)

        # Re-redact from the normalized values, using the schema's own notion of
        # which parameters are credentials rather than a name heuristic.
        record.redacted_parameters = {
            key: "[REDACTED]" if (s := spec.spec_for(key)) and s.secret
            else self.redactor.redact_string(value) if isinstance(value, str) else value
            for key, value in merged.items()
        }
        record.target = spec.target_of(merged)

        record.transition(ExecutionStatus.AUTHORIZED)

        cmd = spec.build_cmd(merged)
        if not cmd:
            return self._fail(record, "BUILD_FAILED", f"failed to build command for {tool_name}", blocked=True)

        # Mask the exact values the schema marked secret, wherever they landed
        # in argv. This is precise where flag-name matching could only guess,
        # and it covers tools whose credential flag nobody thought to list.
        secret_values = [
            str(merged[name]) for name in spec.secret_params()
            if merged.get(name) not in (None, "")
        ]
        record.redacted_command = self.redactor.redact_command(
            list(cmd), secret_values=secret_values
        )

        try:
            workspace = Workspace.create(record.id)
        except WorkspaceError as exc:
            return self._fail(record, "WORKSPACE_ERROR", str(exc), blocked=True)
        record.workspace_path = str(workspace.root)

        if run_async:
            thread = threading.Thread(
                target=self._run_and_record,
                args=(record, cmd, spec.timeout, workspace, cache_key),
                daemon=True,
            )
            thread.start()
            return {"ok": True, "execution_id": record.id, "status": record.status.value, "async": True, "cached": False}

        self._run_and_record(record, cmd, spec.timeout, workspace, cache_key)
        result = self._result(record, include_output=True)
        result["cached"] = False
        return result

    def _run_and_record(
        self, record: ExecutionRecord, cmd, timeout: int, workspace: Workspace,
        cache_key: Optional[str] = None,
    ) -> None:
        """Run the process and fold its outcome into the record."""
        record.transition(ExecutionStatus.RUNNING)
        log.info(_tool_line(
            "RUNNING", record.tool_name, record.target or "",
            f"(risk={record.risk_level})",
        ))
        cancel: Callable[[], bool] = lambda: self.registry.is_cancelled(record.id)

        # Record the OS pid the moment the child starts, so the process is
        # visible in list_processes() while it is still running -- not only
        # after it exits.
        on_spawn: Callable[[int], None] = lambda pid: setattr(record, "pid", pid)

        result = self.runner.run(
            cmd, timeout=timeout, workdir=workspace.root, cancel=cancel, on_spawn=on_spawn
        )

        record.exit_code = result.exit_code
        record.stdout_bytes = result.stdout_bytes
        record.stderr_bytes = result.stderr_bytes
        record.truncated = result.truncated
        record.pid = result.pid
        self._store_output(record.id, result.stdout, result.stderr)

        if result.timed_out:
            record.error_code, record.error_message = "TIMEOUT", result.error
            record.transition(ExecutionStatus.TIMED_OUT)
        elif result.terminated:
            record.error_code, record.error_message = result.error_code, result.error
            record.transition(ExecutionStatus.TERMINATED)
        elif result.error or result.exit_code != 0:
            record.error_code = result.error_code or "NONZERO_EXIT"
            record.error_message = result.error
            record.transition(ExecutionStatus.FAILED)
        else:
            record.transition(ExecutionStatus.COMPLETED)

        self._log_outcome(record)
        self.registry.clear_cancel(record.id)

        # Cache only deterministic terminal outcomes. A timeout or termination
        # is a fact about this run, not a durable answer about the target.
        if cache_key and record.status in (ExecutionStatus.COMPLETED, ExecutionStatus.FAILED):
            self.cache.put(cache_key, self._result(record, include_output=True), record.id)

    def _log_outcome(self, record: ExecutionRecord) -> None:
        """Emit one terminal tool-event line for the logs."""
        status_map = {
            ExecutionStatus.COMPLETED: ("COMPLETED", log.info),
            ExecutionStatus.FAILED: ("FAILED", log.warning),
            ExecutionStatus.TIMED_OUT: ("TIMEOUT", log.warning),
            ExecutionStatus.TERMINATED: ("TERMINATED", log.warning),
        }
        status, emit = status_map.get(record.status, ("FAILED", log.warning))
        duration = record.duration_seconds
        parts = [f"exit={record.exit_code}"] if record.exit_code is not None else []
        if duration is not None:
            parts.append(f"{duration:.2f}s")
        if record.error_code:
            parts.append(f"[{record.error_code}]")
        emit(_tool_line(status, record.tool_name, record.target or "", "  ".join(parts)))

    def _store_output(self, execution_id: str, stdout: str, stderr: str) -> None:
        """Keep the most recent executions' output, dropping the oldest."""
        with self._outputs_lock:
            self._outputs[execution_id] = (stdout, stderr)
            while len(self._outputs) > self._max_outputs:
                self._outputs.popitem(last=False)

    def _get_output(self, execution_id: str) -> tuple:
        with self._outputs_lock:
            return self._outputs.get(execution_id, ("", ""))

    def output(self, execution_id: str, max_bytes: int = 200_000) -> Dict[str, Any]:
        """Return captured output for an execution."""
        record = self.registry.get(execution_id)
        if record is None:
            return _error("NOT_FOUND", f"no such execution: {execution_id}")
        stdout, stderr = self._get_output(execution_id)
        return {
            "ok": True,
            "execution_id": execution_id,
            "status": record.status.value,
            "stdout": self.redactor.redact_string(stdout[:max_bytes]),
            "stderr": self.redactor.redact_string(stderr[:max_bytes]),
            "truncated": record.truncated or len(stdout) > max_bytes,
        }

    def terminate(self, execution_id: str) -> Dict[str, Any]:
        """Request termination of a running execution."""
        record = self.registry.get(execution_id)
        if record is None:
            return _error("NOT_FOUND", f"no such execution: {execution_id}")
        if record.status.is_terminal:
            return _error("NOT_RUNNING", f"execution is already {record.status.value}")
        self.registry.request_cancel(execution_id)
        return {"ok": True, "execution_id": execution_id, "status": "terminating"}

    # -- live process management ------------------------------------------
    # Processes are the running side of executions: there is no separate
    # process table and no second way to spawn or kill. A "process" is just an
    # execution in RUNNING state that has been assigned an OS pid.

    def _running_records(self) -> list:
        return [
            r for r in self.registry.list(ExecutionStatus.RUNNING)
            if r.pid is not None
        ]

    def _resolve(self, ident):
        """Find the running record for an execution id or an OS pid."""
        for record in self._running_records():
            if str(record.id) == str(ident) or str(record.pid) == str(ident):
                return record
        return None

    @staticmethod
    def _process_view(record: ExecutionRecord) -> Dict[str, Any]:
        return {
            "pid": record.pid,
            "execution_id": record.id,
            "tool": record.tool_name,
            "target": record.target,
            "risk_level": record.risk_level,
            "status": record.status.value,
            "uptime_s": record.duration_seconds,
        }

    def list_processes(self) -> list:
        """Every execution currently running, with its live OS pid."""
        return [self._process_view(r) for r in self._running_records()]

    def process_status(self, ident) -> Dict[str, Any]:
        """Live status of one running process, by execution id or pid."""
        record = self._resolve(ident)
        if record is None:
            return _error("NOT_FOUND", f"no running process: {ident}")
        view = self._process_view(record)
        view["ok"] = True
        view["recent_output"] = self._tail_workspace(record)
        return view

    def terminate_process(self, ident) -> Dict[str, Any]:
        """Terminate a running process, by execution id or pid.

        Routes through the same cancellation path as terminate(): the request
        is recorded, the process tree is signalled, and the record moves to
        TERMINATED. There is no raw kill.
        """
        record = self._resolve(ident)
        if record is None:
            return _error("NOT_FOUND", f"no running process: {ident}")
        return self.terminate(record.id)

    def _tail_workspace(self, record: ExecutionRecord, lines: int = 50) -> str:
        """Last few lines of a running execution's stdout, redacted."""
        if not record.workspace_path:
            return ""
        stdout = Path(record.workspace_path) / "stdout.log"
        try:
            text = stdout.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        tail = "\n".join(text.splitlines()[-lines:])
        return self.redactor.redact_string(tail)

    def artifacts(self, execution_id: str) -> Dict[str, Any]:
        """List artifacts produced inside an execution's workspace."""
        record = self.registry.get(execution_id)
        if record is None:
            return _error("NOT_FOUND", f"no such execution: {execution_id}")
        if not record.workspace_path:
            return {"ok": True, "execution_id": execution_id, "artifacts": []}
        workspace = Workspace(
            root=Path(record.workspace_path),
            execution_id=record.id,
        )
        return {"ok": True, "execution_id": execution_id, "artifacts": workspace.list_artifacts()}

    def _fail(self, record: ExecutionRecord, code: str, message: str, blocked: bool) -> Dict[str, Any]:
        record.error_code = code
        record.error_message = message
        record.transition(ExecutionStatus.BLOCKED if blocked else ExecutionStatus.FAILED)
        log.warning(_tool_line(
            "BLOCKED" if blocked else "FAILED",
            record.tool_name, record.target or "", f"[{code}] {message}",
        ))
        return self._result(record, include_output=False)

    def _result(self, record: ExecutionRecord, include_output: bool) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "ok": record.status is ExecutionStatus.COMPLETED,
            "execution_id": record.id,
            "status": record.status.value,
            "exit": record.exit_code,
            "duration_s": record.duration_seconds,
        }
        if record.error_code:
            payload["code"] = record.error_code
            payload["error"] = record.error_message
        if include_output:
            stdout, stderr = self._get_output(record.id)
            payload["output"] = self.redactor.redact_string(stdout)
            payload["stderr"] = self.redactor.redact_string(stderr)
            payload["truncated"] = record.truncated
        return payload


def _error(code: str, message: str) -> Dict[str, Any]:
    return {"ok": False, "code": code, "error": message}
