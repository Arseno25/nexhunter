"""Execution state machine and records."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


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
_ALLOWED_TRANSITIONS: Dict[ExecutionStatus, frozenset] = {
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
    target: Optional[str] = None
    risk_level: str = "active"
    redacted_parameters: Dict[str, Any] = field(default_factory=dict)
    redacted_command: list = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    exit_code: Optional[int] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    workspace_path: Optional[str] = None
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    truncated: bool = False
    pid: Optional[int] = None

    def transition(self, new_status: ExecutionStatus) -> None:
        """Move to a new status, rejecting illegal transitions."""
        allowed = _ALLOWED_TRANSITIONS.get(self.status, frozenset())
        if new_status not in allowed:
            raise InvalidTransition(f"cannot move from {self.status.value} to {new_status.value}")

        self.status = new_status
        if new_status is ExecutionStatus.RUNNING:
            self.started_at = datetime.utcnow()
        elif new_status.is_terminal:
            self.completed_at = datetime.utcnow()

    @property
    def duration_seconds(self) -> Optional[float]:
        """Wall-clock runtime, once the execution has started."""
        if not self.started_at:
            return None
        end = self.completed_at or datetime.utcnow()
        return round((end - self.started_at).total_seconds(), 3)

    def to_dict(self) -> Dict[str, Any]:
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
