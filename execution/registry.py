"""Thread-safe registry of executions.

The HTTP server is threaded, so every mutation of shared execution state goes
through one lock. Records are bounded: a long-running server must not grow its
history without limit.

Optional `path` enables persistence: every mutation atomically rewrites the
registry to that file, and `load` restores it, so execution history survives
server restarts.
"""

import json
import os
import tempfile
import threading
from collections import OrderedDict
from pathlib import Path

from loguru import logger

from nexhunter.execution.models import ExecutionRecord, ExecutionStatus

DEFAULT_MAX_RECORDS = 500


class ExecutionRegistry:
    """In-memory, concurrency-safe store of execution records."""

    def __init__(self, max_records: int = DEFAULT_MAX_RECORDS, path: Path | None = None):
        self._lock = threading.RLock()
        self._records: OrderedDict[str, ExecutionRecord] = OrderedDict()
        self._cancelled: set = set()
        self.max_records = max_records
        self.path: Path | None = path
        if path:
            self.load()

    def load(self) -> None:
        """Restore records persisted by an earlier process."""
        if not self.path or not self.path.is_file():
            return
        try:
            with open(self.path, encoding="utf-8") as handle:
                items = json.load(handle)
            with self._lock:
                for item in items:
                    record = ExecutionRecord.from_dict(item)
                    self._records[record.id] = record
        except (OSError, ValueError, TypeError):
            logger.warning("executions file unreadable, starting empty: {}", self.path)
            self._records.clear()

    def _persist(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = [r.to_dict() for r in self._records.values()]
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            os.replace(tmp, self.path)
        except OSError:
            logger.warning("could not persist executions to {}", self.path)

    def add(self, record: ExecutionRecord) -> ExecutionRecord:
        """Register a new execution, evicting the oldest finished one if full."""
        with self._lock:
            self._records[record.id] = record
            self._evict_locked()
            self._persist()
            return record

    def _evict_locked(self) -> None:
        """Drop oldest terminal records once over capacity. Caller holds lock."""
        while len(self._records) > self.max_records:
            for execution_id, record in self._records.items():
                if record.status.is_terminal:
                    self._records.pop(execution_id)
                    self._cancelled.discard(execution_id)
                    break
            else:
                return  # everything still running; keep them all

    def get(self, execution_id: str) -> ExecutionRecord | None:
        with self._lock:
            return self._records.get(execution_id)

    def list(self, status: ExecutionStatus | None = None) -> list[ExecutionRecord]:
        """Newest first, optionally filtered by status."""
        with self._lock:
            records = list(self._records.values())
        if status:
            records = [r for r in records if r.status is status]
        return sorted(records, key=lambda r: r.created_at, reverse=True)

    def transition(self, execution_id: str, status: ExecutionStatus) -> ExecutionRecord | None:
        """Apply a state transition under the lock."""
        with self._lock:
            record = self._records.get(execution_id)
            if record is None:
                return None
            record.transition(status)
            self._persist()
            return record

    def request_cancel(self, execution_id: str) -> bool:
        """Mark an execution for termination. Returns False if not cancellable."""
        with self._lock:
            record = self._records.get(execution_id)
            if record is None or record.status.is_terminal:
                return False
            self._cancelled.add(execution_id)
            return True

    def is_cancelled(self, execution_id: str) -> bool:
        with self._lock:
            return execution_id in self._cancelled

    def clear_cancel(self, execution_id: str) -> None:
        with self._lock:
            self._cancelled.discard(execution_id)

    def stats(self) -> dict[str, int]:
        """Counts by status, for telemetry and the status endpoint."""
        with self._lock:
            records = list(self._records.values())
        counts: dict[str, int] = {}
        for record in records:
            counts[record.status.value] = counts.get(record.status.value, 0) + 1
        counts["total"] = len(records)
        return counts

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)
