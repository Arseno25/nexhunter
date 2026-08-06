"""Finding storage with fingerprint deduplication."""

import json
import os
import tempfile
import threading
from collections.abc import Iterable
from pathlib import Path

from loguru import logger

from nexhunter.findings.models import Category, Finding, Severity
from nexhunter.security.redaction import SecretRedactor


class FindingStore:
    """Concurrency-safe, deduplicating finding store.

    Findings arrive from parallel tool executions, so this is lock-guarded.
    Deduplication is by fingerprint: the same finding seen twice updates the
    original rather than appending a near-identical row that a reader then has
    to reconcile by hand.

    Optional `path` enables persistence: every mutation atomically rewrites
    the store to that file, and `load` restores it, so history survives server
    restarts. Without a path the store stays purely in-memory.
    """

    def __init__(
        self,
        redactor: SecretRedactor | None = None,
        max_findings: int = 10_000,
        path: Path | None = None,
    ):
        self._lock = threading.RLock()
        self._by_fingerprint: dict[str, Finding] = {}
        self.redactor = redactor or SecretRedactor()
        self.max_findings = max_findings
        self.path: Path | None = path
        if path:
            self.load()

    def load(self) -> None:
        """Restore findings persisted by an earlier process."""
        if not self.path or not self.path.is_file():
            return
        try:
            with open(self.path, encoding="utf-8") as handle:
                items = json.load(handle)
            with self._lock:
                for item in items:
                    finding = Finding.from_dict(item)
                    self._by_fingerprint[finding.fingerprint] = finding
        except (OSError, ValueError, TypeError):
            logger.warning("findings file unreadable, starting empty: {}", self.path)
            self._by_fingerprint.clear()

    def _persist(self) -> None:
        # ponytail: whole-file atomic rewrite per mutation; a journal/append
        # log is the upgrade if a single scan produces thousands of findings.
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = [f.to_dict() for f in self._by_fingerprint.values()]
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            os.replace(tmp, self.path)
        except OSError:
            logger.warning("could not persist findings to {}", self.path)

    def add(self, finding: Finding) -> Finding:
        """Store a finding, merging it into an existing one if already seen."""
        # Evidence comes from the target, which controls it, and routinely
        # contains credentials picked up mid-scan.
        finding.evidence = self.redactor.redact_dict(finding.evidence or {})
        finding.description = self.redactor.redact_string(finding.description or "")

        with self._lock:
            existing = self._by_fingerprint.get(finding.fingerprint)
            if existing is not None:
                existing.merge(finding)
                self._persist()
                return existing

            if len(self._by_fingerprint) >= self.max_findings:
                self._evict_lowest_locked()
            self._by_fingerprint[finding.fingerprint] = finding
            self._persist()
            return finding

    def _evict_lowest_locked(self) -> None:
        """Drop the least severe, oldest finding. Caller holds the lock."""
        if not self._by_fingerprint:
            return
        victim = min(
            self._by_fingerprint.values(),
            key=lambda f: (f.severity.rank, f.last_seen_at),
        )
        self._by_fingerprint.pop(victim.fingerprint, None)

    def add_many(self, findings: Iterable[Finding]) -> list[Finding]:
        return [self.add(finding) for finding in findings]

    def list(
        self,
        severity: Severity | None = None,
        vulnerabilities_only: bool = False,
    ) -> list[Finding]:
        """Findings, most severe first, then most recently seen."""
        with self._lock:
            findings = list(self._by_fingerprint.values())

        if severity:
            findings = [f for f in findings if f.severity.rank >= severity.rank]
        if vulnerabilities_only:
            findings = [f for f in findings if f.is_vulnerability]

        return sorted(findings, key=lambda f: (-f.severity.rank, f.last_seen_at), reverse=False)

    def get(self, finding_id: str) -> Finding | None:
        with self._lock:
            for finding in self._by_fingerprint.values():
                if finding.id == finding_id or finding.fingerprint == finding_id:
                    return finding
        return None

    def summary(self) -> dict:
        """Counts by severity and category, for dashboards and reports."""
        findings = self.list()
        by_severity = {level.value: 0 for level in Severity}
        by_category: dict[str, int] = {}

        for finding in findings:
            by_severity[finding.severity.value] += 1
            by_category[finding.category] = by_category.get(finding.category, 0) + 1

        return {
            "total": len(findings),
            "vulnerabilities": sum(1 for f in findings if f.is_vulnerability),
            "observations": sum(
                1 for f in findings if f.category == Category.OBSERVATION.value
            ),
            "parser_failures": sum(
                1 for f in findings if f.category == Category.PARSER_FAILURE.value
            ),
            "by_severity": by_severity,
            "by_category": by_category,
        }

    def clear(self) -> int:
        """Drop findings; returns how many were removed."""
        with self._lock:
            removed = len(self._by_fingerprint)
            self._by_fingerprint.clear()
            self._persist()
            return removed

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_fingerprint)
