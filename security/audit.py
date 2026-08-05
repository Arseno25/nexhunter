"""Append-only audit log for security-relevant events."""

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from nexhunter.security.authorization import AuthContext
from nexhunter.security.engagement import Engagement, RiskLevel
from nexhunter.security.policy import ExecutionPolicy
from nexhunter.security.redaction import SecretRedactor


DEFAULT_AUDIT_PATH = Path.home() / ".nexhunter" / "audit.jsonl"


class AuditLogger:
    """Write structured audit records to an append-only JSONL file.

    One JSON object per line. Free-text fields are passed through the secret
    redactor; structured identity fields are not, because the audit trail must
    keep recording who did what.
    """

    # Fields that may carry tool output or user-supplied text.
    UNTRUSTED_FIELDS = {"reason", "command", "output", "error", "detail"}

    def __init__(
        self,
        path: Optional[Path] = None,
        redactor: Optional[SecretRedactor] = None,
    ):
        env_path = os.environ.get("NEXHUNTER_AUDIT_LOG")
        self.path = Path(path or env_path or DEFAULT_AUDIT_PATH)
        self.redactor = redactor or SecretRedactor()
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, **fields: Any) -> Dict[str, Any]:
        """Append one audit record. Returns the record as written."""
        record: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
        }
        for key, value in fields.items():
            if value is None:
                continue
            if key in self.UNTRUSTED_FIELDS and isinstance(value, str):
                value = self.redactor.redact_string(value)
            elif isinstance(value, dict):
                value = self.redactor.redact_dict(value)
            elif isinstance(value, (list, tuple)):
                value = self.redactor.redact_list(list(value))
            record[key] = value

        line = json.dumps(record, default=str, sort_keys=True)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        return record

    def log_policy_decision(
        self,
        auth_context: Optional[AuthContext],
        engagement: Optional[Engagement],
        tool_name: str,
        target: str,
        risk_level: RiskLevel,
        policy: ExecutionPolicy,
    ) -> Dict[str, Any]:
        """Record the outcome of a policy engine check."""
        return self.log(
            "policy_decision",
            identity=auth_context.identity if auth_context else "anonymous",
            role=auth_context.role.name if auth_context else None,
            source_ip=auth_context.source_ip if auth_context else None,
            request_id=auth_context.request_id if auth_context else None,
            engagement_id=engagement.id if engagement else None,
            tool=tool_name,
            target=target,
            risk=risk_level.value,
            decision=policy.decision.value,
            policy_code=policy.policy_code,
            requires_approval=policy.requires_approval,
            reason=policy.reason,
        )

    def log_auth_failure(self, source_ip: str, reason: str, request_id: Optional[str] = None) -> Dict[str, Any]:
        """Record a rejected authentication attempt."""
        return self.log(
            "auth_failure",
            source_ip=source_ip,
            request_id=request_id,
            reason=reason,
        )

    def log_execution(
        self,
        auth_context: Optional[AuthContext],
        engagement: Optional[Engagement],
        tool_name: str,
        target: str,
        command: Optional[list] = None,
        exit_code: Optional[int] = None,
        duration_s: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Record an actual tool execution and its outcome."""
        return self.log(
            "execution",
            identity=auth_context.identity if auth_context else "anonymous",
            role=auth_context.role.name if auth_context else None,
            source_ip=auth_context.source_ip if auth_context else None,
            request_id=auth_context.request_id if auth_context else None,
            engagement_id=engagement.id if engagement else None,
            tool=tool_name,
            target=target,
            command=self.redactor.redact_command(command) if command else None,
            exit_code=exit_code,
            duration_s=duration_s,
        )

    def read_records(self, limit: Optional[int] = None) -> list:
        """Read back audit records, newest last. Missing file yields []."""
        if not self.path.exists():
            return []
        with open(self.path, "r", encoding="utf-8") as handle:
            lines = [line for line in handle if line.strip()]
        if limit is not None:
            lines = lines[-limit:]
        return [json.loads(line) for line in lines]


# ponytail: plain JSONL append, no hash chain and no rotation. Add a per-record
# HMAC chain if the log must be tamper-evident, and logrotate/size-based
# rotation if it grows past a single file.
