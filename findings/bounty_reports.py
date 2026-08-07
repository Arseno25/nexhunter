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

from nexhunter.findings import attack, gates
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
    depth_note: str
    cwe_line: str
    attack_line: str
    cvss_line: str
    evidence_block: str
    references_block: str
    artifacts_block: str
    impact_text: str
    remediation_text: str
    root_cause_text: str
    attack_flow_block: str
    attack_chain_block: str


def _gate_note(finding: Finding) -> str:
    if finding.gate_status == "confirmed":
        return ""
    labels = {
        "unreviewed": "**Not yet reviewed** -- no 4-gate verdict has been recorded for this finding.",
        "needs_review": "**Needs review** -- at least one gate came back unsure; verify before submitting.",
        "demoted": "**Demoted** -- clears all four gates, but under a caveat (e.g. requires a "
                   "privileged actor, or impact is bounded) that argues for a lower severity than claimed.",
        "refuted": "**Refuted** -- this finding failed the 4-gate check. Submitting it as-is is not recommended.",
    }
    return labels.get(finding.gate_status, "") + "\n\n"


def _depth_note(depth: str) -> str:
    """Below full confidence, the report itself says what was withheld and
    why -- silently thinning a report reads as a weaker bug than it is,
    which is its own kind of dishonesty."""
    if depth == "lead":
        return (
            "**Lead only** -- review confidence is below 60. Proof of concept and "
            "remediation are withheld until this is confirmed further; treat this as "
            "something to track, not something to submit yet.\n\n"
        )
    if depth == "partial":
        return (
            "**Partial confidence** -- review confidence is 60-79. Remediation is "
            "withheld until this is confirmed further.\n\n"
        )
    return ""


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


def _numbered_block(steps: list[str]) -> str:
    """Canonical Format's Attack Flow / Realistic Attack Chain: one-line
    numbered steps, actor + action. Empty when the reviewer supplied
    nothing -- never invented from evidence that isn't a step sequence."""
    if not steps:
        return ""
    return "\n".join(f"{i}. {step}" for i, step in enumerate(steps, start=1))


def _context(finding: Finding) -> _Context:
    depth = gates.report_depth(finding.review_confidence)
    # 'lead': no PoC, no fix -- confidence too low to hand a defender either.
    # 'partial': PoC stays (it's what earns confidence back), fix withheld.
    evidence_block = "" if depth == "lead" else _evidence_block(finding)
    artifacts_block = "" if depth == "lead" else _artifacts_block(finding)
    remediation_text = "" if depth in ("lead", "partial") else (finding.remediation or "")
    return _Context(
        finding=finding,
        gate_note=_gate_note(finding),
        depth_note=_depth_note(depth),
        cwe_line=_cwe_line(finding),
        attack_line=_attack_line(finding),
        cvss_line=_cvss_line(finding),
        evidence_block=evidence_block,
        references_block=_references_block(finding),
        artifacts_block=artifacts_block,
        impact_text=_impact_text(finding),
        remediation_text=remediation_text,
        root_cause_text=finding.root_cause,
        attack_flow_block=_numbered_block(finding.attack_flow),
        attack_chain_block=_numbered_block(finding.attack_chain_narrative),
    )


def _section(title: str, body: str) -> str:
    """Omit a section entirely when there's nothing to put in it, rather
    than rendering an empty heading a reviewer has to read past. The leading
    `---` matches the Canonical Report Format's divider rule: one between
    the metadata strip and the first section, and between every section
    after it -- appearing only on sections that actually render means no
    dangling divider before an omitted one."""
    return f"---\n\n## {title}\n\n{body}\n\n" if body.strip() else ""


def to_hackerone(finding: Finding) -> str:
    ctx = _context(finding)
    lines = [
        f"# {finding.title}",
        "",
        ctx.gate_note,
        ctx.depth_note,
        f"**Severity:** {finding.severity.value.title()}  ",
        f"**CVSS:** {ctx.cvss_line}  ",
        f"**Weakness:** {ctx.cwe_line or 'not classified'}",
        "",
    ]
    lines.append(_section("Summary", finding.description or finding.title))
    lines.append(_section("Root Cause", ctx.root_cause_text))
    lines.append(_section("Attack Flow", ctx.attack_flow_block))
    lines.append(_section("Steps To Reproduce", ctx.evidence_block))
    lines.append(_section("Supporting Material/References", ctx.references_block or ctx.artifacts_block))
    lines.append(_section("Impact", ctx.impact_text))
    lines.append(_section("Realistic Attack Chain", ctx.attack_chain_block))
    return "\n".join(lines).strip() + "\n"


def to_bugcrowd(finding: Finding) -> str:
    ctx = _context(finding)
    priority = _BUGCROWD_PRIORITY.get(finding.severity.value, "P3")
    lines = [
        f"# {finding.title}",
        "",
        ctx.gate_note,
        ctx.depth_note,
        f"**Bug URL:** {finding.location or finding.target}  ",
        f"**Bug Category (CWE):** {ctx.cwe_line or 'not classified'}  ",
        f"**Priority:** {priority} (mapped from {finding.severity.value} severity, CVSS {ctx.cvss_line})",
        "",
    ]
    lines.append(_section("Description", finding.description or finding.title))
    lines.append(_section("Root Cause", ctx.root_cause_text))
    lines.append(_section("Attack Flow", ctx.attack_flow_block))
    lines.append(_section("Steps to Reproduce", ctx.evidence_block))
    lines.append(_section("Impact", ctx.impact_text))
    lines.append(_section("Realistic Attack Chain", ctx.attack_chain_block))
    lines.append(_section("Suggested Remediation", ctx.remediation_text))
    lines.append(_section("References", ctx.references_block))
    return "\n".join(lines).strip() + "\n"


def to_intigriti(finding: Finding) -> str:
    ctx = _context(finding)
    lines = [
        f"# {finding.title}",
        "",
        ctx.gate_note,
        ctx.depth_note,
        f"**Domain:** {finding.target}  ",
        f"**Vulnerability Type (CWE):** {ctx.cwe_line or 'not classified'}  ",
        f"**Severity (CVSS):** {ctx.cvss_line}  ",
        f"**MITRE ATT&CK:** {ctx.attack_line or 'n/a'}",
        "",
    ]
    lines.append(_section("Description", finding.description or finding.title))
    lines.append(_section("Root Cause", ctx.root_cause_text))
    lines.append(_section("Attack Flow", ctx.attack_flow_block))
    lines.append(_section("Impact", ctx.impact_text))
    lines.append(_section("Steps to Reproduce", ctx.evidence_block))
    lines.append(_section("Proof of Concept", ctx.artifacts_block))
    lines.append(_section("Realistic Attack Chain", ctx.attack_chain_block))
    return "\n".join(lines).strip() + "\n"


def to_immunefi(finding: Finding) -> str:
    ctx = _context(finding)
    # Asset Type / Blockchain-Tech Stack: Immunefi's own required metadata.
    # Only rendered when the finding's evidence actually names them -- never
    # guessed, since NexHunter has no smart-contract tooling to derive them.
    asset_type = str(finding.evidence.get("asset_type", "") or "")
    tech_stack = str(finding.evidence.get("tech_stack", "") or "")
    lines = [
        f"# {finding.title}",
        "",
        ctx.gate_note,
        ctx.depth_note,
        f"**NexHunter severity:** {finding.severity.value.title()} (CVSS {ctx.cvss_line})  ",
    ]
    if asset_type:
        lines.append(f"**Asset Type:** {asset_type}  ")
    if tech_stack:
        lines.append(f"**Blockchain/Tech Stack:** {tech_stack}  ")
    lines += [
        "**Immunefi Impact Category:** _not auto-assigned -- Immunefi rates by fund-loss/",
        "downtime category (Critical/High/Medium/Low), not CVSS; pick the matching category",
        "from the target program's severity matrix before submitting._",
        "",
    ]
    lines.append(_section("Bug Description", finding.description or finding.title))
    lines.append(_section("Root Cause", ctx.root_cause_text))
    lines.append(_section("Attack Flow", ctx.attack_flow_block))
    lines.append(_section("Impact", ctx.impact_text))
    lines.append(_section("Proof of Concept", ctx.evidence_block or ctx.artifacts_block))
    lines.append(_section("Realistic Attack Chain", ctx.attack_chain_block))
    lines.append(_section("Recommendation", ctx.remediation_text))
    return "\n".join(lines).strip() + "\n"


def to_generic(finding: Finding) -> str:
    ctx = _context(finding)
    lines = [
        f"# {finding.title}",
        "",
        ctx.gate_note,
        ctx.depth_note,
        f"**Target:** {finding.target}  ",
        f"**Severity:** {finding.severity.value.title()} (CVSS {ctx.cvss_line})  ",
        f"**Confidence:** {finding.confidence.value}  ",
        f"**Weakness:** {ctx.cwe_line or 'not classified'}  ",
        f"**MITRE ATT&CK:** {ctx.attack_line or 'n/a'}",
        "",
    ]
    lines.append(_section("Description", finding.description or finding.title))
    lines.append(_section("Root Cause", ctx.root_cause_text))
    lines.append(_section("Attack Flow", ctx.attack_flow_block))
    lines.append(_section("Impact", ctx.impact_text))
    lines.append(_section("Realistic Attack Chain", ctx.attack_chain_block))
    lines.append(_section("Steps to Reproduce", ctx.evidence_block))
    lines.append(_section("Remediation", ctx.remediation_text))
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
