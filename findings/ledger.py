"""Store-wide integrity audit.

The per-finding analogue is gates.py (does this one finding survive the 4
gates); this is the store-wide check: does every finding that claims to be
confirmed or demoted actually have evidence behind that claim, and is every
finding's chain of custody (custody.py) still intact. Read-only -- this
reports issues, it never fixes or drops a finding on its own.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from nexhunter.findings import custody

if TYPE_CHECKING:
    from nexhunter.findings.models import Finding


@dataclass(frozen=True)
class LedgerIssue:
    finding_id: str
    kind: str  # "no_evidence" | "custody_broken"
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"finding_id": self.finding_id, "kind": self.kind, "detail": self.detail}


def audit(findings: "list[Finding]") -> list[LedgerIssue]:
    """Walk every finding and report what doesn't hold up.

    no_evidence: disposition is confirmed/demoted (i.e. survived the 4
    gates) but there is neither evidence nor an artifact behind it -- a
    claim with nothing to show for it.
    custody_broken: the finding's audit trail hash chain doesn't verify,
    meaning a stored link was altered after it was written.
    """
    issues: list[LedgerIssue] = []
    for finding in findings:
        if finding.disposition in ("confirmed", "demoted") and not finding.evidence and not finding.artifacts:
            issues.append(LedgerIssue(
                finding.id, "no_evidence",
                "disposition is confirmed/demoted but evidence and artifacts are both empty",
            ))
        intact, reason = custody.verify(finding.custody_chain)
        if not intact:
            issues.append(LedgerIssue(finding.id, "custody_broken", reason or "custody chain hash mismatch"))
    return issues


__all__ = ["LedgerIssue", "audit"]
