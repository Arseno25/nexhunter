"""Batch triage: bucket findings by disposition, most severe first.

The store-wide view of gates.disposition() -- supervisor.md's Batch Triage
Mode output (CONFIRMED / LEADS / KILLED), generalized to all six
dispositions instead of three, since NexHunter already tracks the finer
distinction (demoted vs needs_review vs refuted) rather than collapsing
them.
"""

from typing import TYPE_CHECKING

from nexhunter.findings.gates import Disposition

if TYPE_CHECKING:
    from nexhunter.findings.models import Finding

BUCKET_ORDER: tuple[str, ...] = tuple(d.value for d in Disposition)


def buckets(findings: "list[Finding]") -> dict[str, "list[Finding]"]:
    """Group findings by disposition, each bucket sorted most severe first.

    Every bucket name in BUCKET_ORDER is always present, even if empty --
    a caller can iterate the dict without checking for missing keys.
    """
    result: dict[str, list[Finding]] = {name: [] for name in BUCKET_ORDER}
    for finding in findings:
        result[finding.disposition].append(finding)
    for group in result.values():
        group.sort(key=lambda f: -f.severity.rank)
    return result


__all__ = ["BUCKET_ORDER", "buckets"]
