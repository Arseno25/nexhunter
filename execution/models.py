"""Execution state machine and records."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ExecutionStatus(Enum):
    """Lifecycle of a single tool execution."""

    QUEUED = "queued"
    VALIDATING = "validating"
    AUTHORIZED = "authorized"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    TERMINATED = "terminated"
    BLOCKED = "blocked"

    @property
    def is_terminal(self) -> bool:
        """True once no further transition is possible."""
        return self in _TERMINAL_STATES


_TERMINAL_STATES = {
    ExecutionStatus.COMPLETED,
    ExecutionStatus.FAILED,
    ExecutionStatus.TIMED_OUT,
    ExecutionStatus.TERMINATED,
    ExecutionStatus.BLOCKED,
}

# Only these transitions are legal. Anything else is a bug in the caller and
# raises rather than silently corrupting the record.
_ALLOWED_TRANSITIONS: dict[ExecutionStatus, frozenset] = {
    ExecutionStatus.QUEUED: frozenset({ExecutionStatus.VALIDATING, ExecutionStatus.BLOCKED, ExecutionStatus.FAILED}),
    ExecutionStatus.VALIDATING: frozenset({ExecutionStatus.AUTHORIZED, ExecutionStatus.BLOCKED, ExecutionStatus.FAILED}),
    ExecutionStatus.AUTHORIZED: frozenset({ExecutionStatus.RUNNING, ExecutionStatus.BLOCKED, ExecutionStatus.FAILED}),
    ExecutionStatus.RUNNING: frozenset({
        ExecutionStatus.COMPLETED,
        ExecutionStatus.FAILED,
        ExecutionStatus.TIMED_OUT,
        ExecutionStatus.TERMINATED,
    }),
}


class InvalidTransition(Exception):
    """An illegal execution state transition was attempted."""


@dataclass
class ExecutionRecord:
    """One tool execution, from request through to terminal state.

    The OS process id is deliberately not the public identifier: pids are
    reused by the kernel and mean nothing once the process exits.
    """

    tool_name: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    status: ExecutionStatus = ExecutionStatus.QUEUED
    target: str | None = None
    risk_level: str = "active"
    redacted_parameters: dict[str, Any] = field(default_factory=dict)
    redacted_command: list = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    exit_code: int | None = None
    error_code: str | None = None
    error_message: str | None = None
    workspace_path: str | None = None
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    truncated: bool = False
    pid: int | None = None

    def transition(self, new_status: ExecutionStatus) -> None:
        """Move to a new status, rejecting illegal transitions."""
        allowed = _ALLOWED_TRANSITIONS.get(self.status, frozenset())
        if new_status not in allowed:
            raise InvalidTransition(f"cannot move from {self.status.value} to {new_status.value}")

        self.status = new_status
        if new_status is ExecutionStatus.RUNNING:
            self.started_at = datetime.now(timezone.utc)
        elif new_status.is_terminal:
            self.completed_at = datetime.now(timezone.utc)

    @property
    def duration_seconds(self) -> float | None:
        """Wall-clock runtime, once the execution has started."""
        if not self.started_at:
            return None
        end = self.completed_at or datetime.now(timezone.utc)
        return round((end - self.started_at).total_seconds(), 3)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExecutionRecord":
        """Rebuild from `to_dict` output (persistence round-trip).

        Records that were mid-flight when the server died are honest about it:
        they come back as FAILED rather than pretending to be running. Pid and
        workspace are deliberately not restored -- pids are meaningless after a
        restart and workspaces are derivable from the execution id.
        """
        status = ExecutionStatus(data.get("status", ExecutionStatus.QUEUED.value))
        if not status.is_terminal:
            status = ExecutionStatus.FAILED
            message = data.get("error") or "server restarted mid-execution"
        else:
            message = data.get("error")

        def _dt(key: str) -> datetime | None:
            value = data.get(key)
            return datetime.fromisoformat(value) if value else None

        return cls(
            tool_name=data.get("tool", ""),
            id=data.get("id") or uuid.uuid4().hex,
            status=status,
            target=data.get("target"),
            risk_level=data.get("risk_level", "active"),
            redacted_parameters=data.get("parameters") or {},
            redacted_command=data.get("command") or [],
            created_at=_dt("created_at") or datetime.now(timezone.utc),
            started_at=_dt("started_at"),
            completed_at=_dt("completed_at"),
            exit_code=data.get("exit_code"),
            error_code=data.get("error_code"),
            error_message=message,
            stdout_bytes=data.get("stdout_bytes", 0),
            stderr_bytes=data.get("stderr_bytes", 0),
            truncated=bool(data.get("truncated", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        """Dashboard-ready view. Contains no unredacted parameters."""
        return {
            "id": self.id,
            "tool": self.tool_name,
            "status": self.status.value,
            "target": self.target,
            "risk_level": self.risk_level,
            "parameters": self.redacted_parameters,
            "command": self.redacted_command,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_s": self.duration_seconds,
            "exit_code": self.exit_code,
            "error_code": self.error_code,
            "error": self.error_message,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "truncated": self.truncated,
        }
