"""The single execution path.

Both the REST API and the MCP server call `ExecutionService.execute()`. Neither
builds commands or spawns processes on its own -- that is what keeps the two
interfaces from drifting apart.

Order of operations:

    validate params -> build argv -> run -> record
"""

import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from nexhunter.core import tools as T
from nexhunter.execution.models import ExecutionRecord, ExecutionStatus
from nexhunter.execution.registry import ExecutionRegistry
from nexhunter.execution.runner import ProcessRunner, RunResult
from nexhunter.execution.workspace import Workspace, WorkspaceError
from nexhunter.security.redaction import SecretRedactor


class ExecutionService:
    """Validate, build, run, and record one tool execution."""

    def __init__(
        self,
        registry: Optional[ExecutionRegistry] = None,
        runner: Optional[ProcessRunner] = None,
        redactor: Optional[SecretRedactor] = None,
    ):
        self.registry = registry or ExecutionRegistry()
        self.runner = runner or ProcessRunner()
        self.redactor = redactor or SecretRedactor()
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
    ) -> Dict[str, Any]:
        """Run one registered tool. Returns an API-shaped result dict."""
        spec = T.get_tool_spec(tool_name)
        if spec is None:
            return _error("UNKNOWN_TOOL", f"unknown tool: {tool_name}")

        params = params or {}
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
                args=(record, cmd, spec.timeout, workspace),
                daemon=True,
            )
            thread.start()
            return {"ok": True, "execution_id": record.id, "status": record.status.value, "async": True}

        self._run_and_record(record, cmd, spec.timeout, workspace)
        return self._result(record, include_output=True)

    def _run_and_record(self, record: ExecutionRecord, cmd, timeout: int, workspace: Workspace) -> None:
        """Run the process and fold its outcome into the record."""
        record.transition(ExecutionStatus.RUNNING)
        cancel: Callable[[], bool] = lambda: self.registry.is_cancelled(record.id)

        result = self.runner.run(cmd, timeout=timeout, workdir=workspace.root, cancel=cancel)

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

        self.registry.clear_cancel(record.id)

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
