"""The normalized finding model.

One shape for every tool's output, so results can be compared, deduplicated,
and exported. The rules that matter most here are about restraint: a finding
records what a tool observed, not what it might imply. Inventing a CVE, a CVSS
score, or a remediation that the evidence does not support turns a scanner
into a fiction generator, and the person reading the report cannot tell the
difference.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """Normalized severity. Tool-specific scales map onto these."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# How other tools spell the same thing.
_SEVERITY_ALIASES = {
    "critical": Severity.CRITICAL, "crit": Severity.CRITICAL, "severe": Severity.CRITICAL,
    "blocker": Severity.CRITICAL, "5": Severity.CRITICAL,
    "high": Severity.HIGH, "error": Severity.HIGH, "major": Severity.HIGH, "4": Severity.HIGH,
    "medium": Severity.MEDIUM, "moderate": Severity.MEDIUM, "warning": Severity.MEDIUM,
    "warn": Severity.MEDIUM, "3": Severity.MEDIUM,
    "low": Severity.LOW, "minor": Severity.LOW, "note": Severity.LOW, "2": Severity.LOW,
    "info": Severity.INFO, "informational": Severity.INFO, "information": Severity.INFO,
    "unknown": Severity.INFO, "none": Severity.INFO, "1": Severity.INFO, "0": Severity.INFO,
}


def normalize_severity(value: Any) -> Severity:
    """Map a tool's severity onto the normalized scale.

    Anything unrecognized becomes INFO rather than a guess at something worse:
    inflating an unknown value would make the report louder without making it
    more true.
    """
    if isinstance(value, Severity):
        return value
    if value is None:
        return Severity.INFO

    text = str(value).strip().lower()
    if text in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[text]

    # A CVSS-style number, if it is genuinely one.
    try:
        score = float(text)
    except ValueError:
        return Severity.INFO
    return severity_from_cvss(score)


def severity_from_cvss(score: float) -> Severity:
    """CVSS v3 qualitative rating."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


class Confidence(Enum):
    """How firmly the evidence supports the finding."""

    CONFIRMED = "confirmed"   # verified by the tool, not inferred
    FIRM = "firm"             # strong evidence, no verification step
    TENTATIVE = "tentative"   # pattern match or inference

    @staticmethod
    def parse(value: Any) -> "Confidence":
        if isinstance(value, Confidence):
            return value
        text = str(value or "").strip().lower()
        for candidate in Confidence:
            if candidate.value == text:
                return candidate
        if text in {"certain", "high", "verified"}:
            return Confidence.CONFIRMED
        if text in {"medium", "probable"}:
            return Confidence.FIRM
        return Confidence.TENTATIVE


class Category(str, Enum):
    """What kind of statement a finding is making.

    The distinction between an observation and a vulnerability is the whole
    point: "port 22 is open" and "this service is exploitable" are different
    claims, and conflating them is how scanners produce alarming nonsense.
    """

    OBSERVATION = "observation"       # a fact about the target
    VULNERABILITY = "vulnerability"   # a weakness, with evidence
    MISCONFIGURATION = "misconfiguration"
    EXPOSURE = "exposure"             # something reachable that should not be
    SECRET = "secret"
    PARSER_FAILURE = "parser_failure"  # we could not read the tool's output


_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CWE = re.compile(r"^CWE-\d+$", re.IGNORECASE)


@dataclass
class Finding:
    """One normalized result.

    `fingerprint` is a SHA-256 over the identifying fields, so the same finding
    seen twice collapses to one record with an updated last_seen_at.
    """

    tool: str
    target: str
    title: str
    execution_id: str = ""
    category: str = Category.OBSERVATION.value
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.TENTATIVE
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    location: Optional[str] = None      # file path, URL path, or port
    first_seen_at: datetime = field(default_factory=datetime.utcnow)
    last_seen_at: datetime = field(default_factory=datetime.utcnow)
    id: str = ""

    def __post_init__(self):
        self.severity = normalize_severity(self.severity)
        self.confidence = Confidence.parse(self.confidence)

        # Identifiers are only kept when they are real. A malformed CVE id is
        # dropped rather than passed along to a reader who will trust it.
        self.cve_ids = [c.upper() for c in self.cve_ids if _CVE.match(str(c))]
        self.cwe_ids = [c.upper() for c in self.cwe_ids if _CWE.match(str(c))]

        if self.cvss_score is not None:
            try:
                score = float(self.cvss_score)
            except (TypeError, ValueError):
                score = None
            self.cvss_score = score if score is not None and 0.0 <= score <= 10.0 else None

        if not self.id:
            self.id = self.fingerprint[:16]

    @property
    def fingerprint(self) -> str:
        """Stable identity: same finding, same fingerprint, across runs.

        Deliberately excludes timestamps, execution id, and severity, so a
        rerun or a severity reclassification does not create a duplicate.
        """
        material = json.dumps(
            {
                "tool": self.tool,
                "target": self.target.lower(),
                "title": self.title.strip().lower(),
                "category": self.category,
                "location": (self.location or "").lower(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode()).hexdigest()

    @property
    def is_vulnerability(self) -> bool:
        """True only for categories that actually assert a weakness."""
        return self.category in {
            Category.VULNERABILITY.value,
            Category.MISCONFIGURATION.value,
            Category.EXPOSURE.value,
            Category.SECRET.value,
        }

    def merge(self, other: "Finding") -> None:
        """Fold a repeat sighting into this record."""
        self.last_seen_at = max(self.last_seen_at, other.last_seen_at)
        if other.severity.rank > self.severity.rank:
            self.severity = other.severity
        for source, destination in (
            (other.cve_ids, self.cve_ids),
            (other.cwe_ids, self.cwe_ids),
            (other.references, self.references),
        ):
            for item in source:
                if item not in destination:
                    destination.append(item)
        if self.cvss_score is None:
            self.cvss_score = other.cvss_score
        if not self.remediation:
            self.remediation = other.remediation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "execution_id": self.execution_id,
            "tool": self.tool,
            "target": self.target,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "cvss_score": self.cvss_score,
            "location": self.location,
            "is_vulnerability": self.is_vulnerability,
            "first_seen_at": self.first_seen_at.isoformat(),
            "last_seen_at": self.last_seen_at.isoformat(),
        }

    @classmethod
    def parser_failure(cls, tool: str, target: str, reason: str, **kwargs) -> "Finding":
        """A finding recording that we could not read a tool's output.

        Kept as a finding rather than swallowed, because "the parser broke" and
        "the tool found nothing" look identical in a report otherwise, and only
        one of them means the target is clean.
        """
        return cls(
            tool=tool,
            target=target,
            title=f"Could not parse {tool} output",
            category=Category.PARSER_FAILURE.value,
            description=reason,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            **kwargs,
        )
