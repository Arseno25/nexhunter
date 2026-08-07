"""Submission-ready bug bounty reports, one finding at a time.

Different shape from export.py on purpose: export.py renders a whole ledger
(every finding, one report), this renders the single write-up a human pastes
into a platform's submission form. Each platform has its own required
section order and field names -- that's the "profile" this module matches --
but they all draw from the same Finding, so the shared pieces (evidence,
CVSS line, CWE/ATT&CK labels, remediation) are built once in _context() and
each template only decides how to arrange them.

Two restraint rules carried over from the rest of findings/:
  - A finding that hasn't cleared the 4-gate check (gates.py) is still
    rendered -- the operator may want a draft -- but the report says so up
    front rather than presenting an unreviewed claim as confirmed.
  - Immunefi's severity classification is impact-category-based (fund loss,
    downtime), not CVSS-based; mapping a generic CVSS score onto it would be
    a fabricated equivalence, so that template surfaces NexHunter's own
    severity and says explicitly that Immunefi's category still needs to be
    picked by hand.
"""

import json
from dataclasses import dataclass

from nexhunter.findings import attack
from nexhunter.findings.models import Finding

# Bugcrowd's own 5-point priority scale; this is a documented, deterministic
# mapping from the normalized severity rank, not a guess.
_BUGCROWD_PRIORITY = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
    "info": "P5",
}


@dataclass
class _Context:
    finding: Finding
    gate_note: str
    cwe_line: str
    attack_line: str
    cvss_line: str
    evidence_block: str
    references_block: str
    artifacts_block: str
    impact_text: str


def _gate_note(finding: Finding) -> str:
    if finding.gate_status == "confirmed":
        return ""
    labels = {
        "unreviewed": "**Not yet reviewed** -- no 4-gate verdict has been recorded for this finding.",
        "needs_review": "**Needs review** -- at least one gate came back unsure; verify before submitting.",
        "refuted": "**Refuted** -- this finding failed the 4-gate check. Submitting it as-is is not recommended.",
    }
    return labels.get(finding.gate_status, "") + "\n\n"


def _cwe_line(finding: Finding) -> str:
    return ", ".join(finding.cwe_ids) if finding.cwe_ids else ""


def _attack_line(finding: Finding) -> str:
    if not finding.attack_ids:
        return ""
    return ", ".join(
        f"{tid} ({attack.attack_name(tid)})" if attack.attack_name(tid) else tid for tid in finding.attack_ids
    )


def _cvss_line(finding: Finding) -> str:
    if finding.cvss_vector:
        return f"{finding.cvss_score} ({finding.cvss_vector})"
    if finding.cvss_score is not None:
        return str(finding.cvss_score)
    return "not scored"


def _evidence_block(finding: Finding) -> str:
    if not finding.evidence:
        return ""
    return "```json\n" + json.dumps(finding.evidence, indent=2) + "\n```"


def _references_block(finding: Finding) -> str:
    if not finding.references:
        return ""
    return "\n".join(f"- {r}" for r in finding.references)


def _artifacts_block(finding: Finding) -> str:
    if not finding.artifacts:
        return ""
    return "\n".join(f"- `{a}`" for a in finding.artifacts)


def _impact_text(finding: Finding) -> str:
    """The only non-fabricated source of impact narrative: the reasoning an
    AI or human already wrote down for the 'impact' gate (gates.py) when
    reviewing this finding -- "is there material harm to an identifiable
    victim?" is exactly the impact question a report needs answered. Empty
    when the finding hasn't been through gate review yet, rather than
    inventing an impact statement from evidence that doesn't describe one."""
    return finding.gate_notes.get("impact", "")


def _context(finding: Finding) -> _Context:
    return _Context(
        finding=finding,
        gate_note=_gate_note(finding),
        cwe_line=_cwe_line(finding),
        attack_line=_attack_line(finding),
        cvss_line=_cvss_line(finding),
        evidence_block=_evidence_block(finding),
        references_block=_references_block(finding),
        artifacts_block=_artifacts_block(finding),
        impact_text=_impact_text(finding),
    )


def _section(title: str, body: str) -> str:
    """Omit a section entirely when there's nothing to put in it, rather
    than rendering an empty heading a reviewer has to read past."""
    return f"## {title}\n\n{body}\n\n" if body.strip() else ""


def to_hackerone(finding: Finding) -> str:
    ctx = _context(finding)
    lines = [
        f"# {finding.title}",
        "",
        ctx.gate_note,
        f"**Severity:** {finding.severity.value.title()}  ",
        f"**CVSS:** {ctx.cvss_line}  ",
        f"**Weakness:** {ctx.cwe_line or 'not classified'}",
        "",
    ]
    lines.append(_section("Summary", finding.description or finding.title))
    lines.append(_section("Steps To Reproduce", ctx.evidence_block))
    lines.append(_section("Supporting Material/References", ctx.references_block or ctx.artifacts_block))
    lines.append(_section("Impact", ctx.impact_text))
    return "\n".join(lines).strip() + "\n"


def to_bugcrowd(finding: Finding) -> str:
    ctx = _context(finding)
    priority = _BUGCROWD_PRIORITY.get(finding.severity.value, "P3")
    lines = [
        f"# {finding.title}",
        "",
        ctx.gate_note,
        f"**Bug URL:** {finding.location or finding.target}  ",
        f"**Bug Category (CWE):** {ctx.cwe_line or 'not classified'}  ",
        f"**Priority:** {priority} (mapped from {finding.severity.value} severity, CVSS {ctx.cvss_line})",
        "",
    ]
    lines.append(_section("Description", finding.description or finding.title))
    lines.append(_section("Steps to Reproduce", ctx.evidence_block))
    lines.append(_section("Impact", ctx.impact_text))
    lines.append(_section("Suggested Remediation", finding.remediation or ""))
    lines.append(_section("References", ctx.references_block))
    return "\n".join(lines).strip() + "\n"


def to_intigriti(finding: Finding) -> str:
    ctx = _context(finding)
    lines = [
        f"# {finding.title}",
        "",
        ctx.gate_note,
        f"**Domain:** {finding.target}  ",
        f"**Vulnerability Type (CWE):** {ctx.cwe_line or 'not classified'}  ",
        f"**Severity (CVSS):** {ctx.cvss_line}  ",
        f"**MITRE ATT&CK:** {ctx.attack_line or 'n/a'}",
        "",
    ]
    lines.append(_section("Description", finding.description or finding.title))
    lines.append(_section("Impact", ctx.impact_text))
    lines.append(_section("Steps to Reproduce", ctx.evidence_block))
    lines.append(_section("Proof of Concept", ctx.artifacts_block))
    return "\n".join(lines).strip() + "\n"


def to_immunefi(finding: Finding) -> str:
    ctx = _context(finding)
    lines = [
        f"# {finding.title}",
        "",
        ctx.gate_note,
        f"**NexHunter severity:** {finding.severity.value.title()} (CVSS {ctx.cvss_line})  ",
        "**Immunefi Impact Category:** _not auto-assigned -- Immunefi rates by fund-loss/",
        "downtime category (Critical/High/Medium/Low), not CVSS; pick the matching category",
        "from the target program's severity matrix before submitting._",
        "",
    ]
    lines.append(_section("Bug Description", finding.description or finding.title))
    lines.append(_section("Impact", ctx.impact_text))
    lines.append(_section("Proof of Concept", ctx.evidence_block or ctx.artifacts_block))
    lines.append(_section("Recommendation", finding.remediation or ""))
    return "\n".join(lines).strip() + "\n"


def to_generic(finding: Finding) -> str:
    ctx = _context(finding)
    lines = [
        f"# {finding.title}",
        "",
        ctx.gate_note,
        f"**Target:** {finding.target}  ",
        f"**Severity:** {finding.severity.value.title()} (CVSS {ctx.cvss_line})  ",
        f"**Confidence:** {finding.confidence.value}  ",
        f"**Weakness:** {ctx.cwe_line or 'not classified'}  ",
        f"**MITRE ATT&CK:** {ctx.attack_line or 'n/a'}",
        "",
    ]
    lines.append(_section("Description", finding.description or finding.title))
    lines.append(_section("Impact", ctx.impact_text))
    lines.append(_section("Steps to Reproduce", ctx.evidence_block))
    lines.append(_section("Remediation", finding.remediation or ""))
    lines.append(_section("References", ctx.references_block))
    lines.append(_section("Artifacts", ctx.artifacts_block))
    return "\n".join(lines).strip() + "\n"


PLATFORMS = {
    "hackerone": to_hackerone,
    "h1": to_hackerone,
    "bugcrowd": to_bugcrowd,
    "intigriti": to_intigriti,
    "immunefi": to_immunefi,
    "generic": to_generic,
}


def render(finding: Finding, platform: str = "generic") -> str:
    """Render one finding as a submission-ready report for the named platform."""
    key = (platform or "generic").strip().lower()
    if key not in PLATFORMS:
        raise ValueError(f"unknown platform {platform!r}; available: {', '.join(sorted(set(PLATFORMS)))}")
    return PLATFORMS[key](finding)


__all__ = [
    "PLATFORMS",
    "render",
    "to_hackerone",
    "to_bugcrowd",
    "to_intigriti",
    "to_immunefi",
    "to_generic",
]
