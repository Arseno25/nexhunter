"""Finding storage with fingerprint deduplication."""

import threading
from typing import Dict, Iterable, List, Optional

from nexhunter.findings.models import Category, Finding, Severity
from nexhunter.security.redaction import SecretRedactor


class FindingStore:
    """Concurrency-safe, deduplicating finding store.

    Findings arrive from parallel tool executions, so this is lock-guarded.
    Deduplication is by fingerprint: the same finding seen twice updates the
    original rather than appending a near-identical row that a reader then has
    to reconcile by hand.
    """

    def __init__(self, redactor: Optional[SecretRedactor] = None, max_findings: int = 10_000):
        self._lock = threading.RLock()
        self._by_fingerprint: Dict[str, Finding] = {}
        self.redactor = redactor or SecretRedactor()
        self.max_findings = max_findings

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
                return existing

            if len(self._by_fingerprint) >= self.max_findings:
                self._evict_lowest_locked()
            self._by_fingerprint[finding.fingerprint] = finding
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

    def add_many(self, findings: Iterable[Finding]) -> List[Finding]:
        return [self.add(finding) for finding in findings]

    def list(
        self,
        severity: Optional[Severity] = None,
        vulnerabilities_only: bool = False,
    ) -> List[Finding]:
        """Findings, most severe first, then most recently seen."""
        with self._lock:
            findings = list(self._by_fingerprint.values())

        if severity:
            findings = [f for f in findings if f.severity.rank >= severity.rank]
        if vulnerabilities_only:
            findings = [f for f in findings if f.is_vulnerability]

        return sorted(findings, key=lambda f: (-f.severity.rank, f.last_seen_at), reverse=False)

    def get(self, finding_id: str) -> Optional[Finding]:
        with self._lock:
            for finding in self._by_fingerprint.values():
                if finding.id == finding_id or finding.fingerprint == finding_id:
                    return finding
        return None

    def summary(self) -> dict:
        """Counts by severity and category, for dashboards and reports."""
        findings = self.list()
        by_severity = {level.value: 0 for level in Severity}
        by_category: Dict[str, int] = {}

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
            return removed

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_fingerprint)
