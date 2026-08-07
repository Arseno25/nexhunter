"""The 4-gate finding validator.

A tool observation and a confirmed vulnerability are different claims (see
the Category docstring in models.py); this is the step between them. Each
gate asks one question about the finding:

    refutation    can the attack be concretely blocked by an existing guard?
    reachability  can the vulnerable state exist in a live deployment?
    trigger       can an unprivileged actor execute it?
    impact        is there material harm to an identifiable victim?

Answering these requires reading code and reasoning about intent -- that is
a judgment call, not something computable from tool output, so this module
never makes it. A caller (an AI client, reasoning over the finding and its
evidence, or a human reviewer) submits one verdict per gate; this module only
does the part that *is* mechanical: validating the shape of what was
submitted and aggregating four verdicts into one status. It never invents a
verdict the way it never invents a CVSS score or a CVE ID.

The four-verdict vocabulary (pass/fail/demote/unsure per gate) matches the
reference this was ported from -- gates.py's aggregate() is the deterministic
replacement for a step that reference leaves to an LLM's free-text final
verdict. Trusting AI-written prose as the finding's disposition, with no
structural cross-check, is exactly the "unverified claim" the rest of
NexHunter refuses to make; aggregate() is code, not prose, precisely so the
final status is always reproducible from the four verdicts that produced it.
"""

from enum import Enum


class GateVerdict(str, Enum):
    PASS = "pass"        # noqa: S105 - a gate verdict, not a hardcoded credential
    FAIL = "fail"          # gate not satisfied -- refutes the finding outright
    DEMOTE = "demote"      # gate technically clears, but only under a caveat
                           # (requires a privileged/trusted actor, impact is
                           # bounded, timing-dependent...) that argues for a
                           # lower severity rather than outright rejection
    UNSURE = "unsure"      # evidence does not clearly settle this gate

    @staticmethod
    def parse(value) -> "GateVerdict":
        text = str(value or "").strip().lower()
        for candidate in GateVerdict:
            if candidate.value == text:
                return candidate
        raise ValueError(f"gate verdict must be one of {[v.value for v in GateVerdict]}, got {value!r}")


class GateStatus(str, Enum):
    UNREVIEWED = "unreviewed"      # no gate verdicts submitted yet
    CONFIRMED = "confirmed"        # all four gates passed cleanly
    DEMOTED = "demoted"            # no failures, but at least one DEMOTE --
                                    # stands, but severity should be reconsidered
    REFUTED = "refuted"            # at least one gate failed
    NEEDS_REVIEW = "needs_review"  # no failures/demotes, but at least one UNSURE


GATE_NAMES: tuple[str, ...] = ("refutation", "reachability", "trigger", "impact")


def aggregate(verdicts: dict[str, GateVerdict]) -> GateStatus:
    """Roll up four per-gate verdicts into one status.

    A single FAIL refutes the finding outright, regardless of the others --
    matches the gate's own definition: "fail any gate -> rejected". DEMOTE
    outranks UNSURE: a finding with a known caveat (e.g. "only a privileged
    actor can trigger this") is a more finished assessment than one with
    unresolved evidence, so it gets its own status rather than being lumped
    into "needs review".
    """
    values = [verdicts[name] for name in GATE_NAMES]
    if any(v == GateVerdict.FAIL for v in values):
        return GateStatus.REFUTED
    if any(v == GateVerdict.DEMOTE for v in values):
        return GateStatus.DEMOTED
    if any(v == GateVerdict.UNSURE for v in values):
        return GateStatus.NEEDS_REVIEW
    return GateStatus.CONFIRMED


def parse_verdicts(payload: dict) -> dict[str, GateVerdict]:
    """Parse and validate the four gate fields from a request body.

    Raises ValueError naming the first problem found, so a caller gets one
    clear reason rather than a partial/ambiguous result.
    """
    missing = [name for name in GATE_NAMES if name not in payload]
    if missing:
        raise ValueError(f"missing gate verdict(s): {', '.join(missing)}")
    return {name: GateVerdict.parse(payload[name]) for name in GATE_NAMES}


def notes_from(payload: dict) -> dict[str, str]:
    """Extract the optional `<gate>_notes` reasoning text for each gate."""
    return {name: str(payload.get(f"{name}_notes", "") or "") for name in GATE_NAMES}


def gateable(is_vulnerability: bool) -> bool:
    """Only a claim that actually asserts a weakness needs gating.

    An OBSERVATION ("port 22 is open") or a PARSER_FAILURE makes no exploit
    claim to refute or confirm -- callers pass Finding.is_vulnerability.
    """
    return is_vulnerability


# Confidence: how much of the report a review has actually earned. Distinct
# from a gate verdict (which asks "does this survive?") and from
# Finding.confidence (a parser's confidence in its raw observation, set
# before any review happens) -- this is "how much of the finding is
# demonstrated, versus argued". Deductions are named, fixed, and only ever
# applied when the reviewer says the condition is true; there is no formula
# that guesses at any of them from evidence.
CONFIDENCE_DEDUCTIONS: dict[str, int] = {
    "partial_attack_path": 20,       # some steps demonstrated, not the full chain
    "bounded_impact": 15,            # real but capped -- can't compound or scale
    "requires_specific_state": 10,   # needs a state that's achievable but not the default
    "requires_user_interaction": 10, # a victim has to do something, not fully unattended
    "fix_partially_mitigates": 10,   # a control already narrows the exposure
}


def confidence_score(flags: dict[str, bool]) -> int:
    """Score 0-100: 100 minus one deduction per flag the reviewer marked
    true. Unknown keys in `flags` are ignored -- this only ever subtracts for
    conditions the reviewer explicitly asserted, never invents one.

    >= 80: full report -- description, PoC, and remediation.
    60-79: description and a partial PoC.
    <  60: lead only -- track it, but no PoC/remediation until confirmed
    further (see bounty_reports.render's report_depth).
    """
    score = 100
    for key, penalty in CONFIDENCE_DEDUCTIONS.items():
        if flags.get(key):
            score -= penalty
    return max(0, score)


def report_depth(confidence: int | None) -> str:
    """Map a confidence score onto how much of the report to render.

    None (never scored) renders as 'full' -- confidence scoring is opt-in;
    a finding nobody scored is not penalized for it.
    """
    if confidence is None or confidence >= 80:
        return "full"
    if confidence >= 60:
        return "partial"
    return "lead"


__all__ = [
    "GateVerdict",
    "GateStatus",
    "GATE_NAMES",
    "CONFIDENCE_DEDUCTIONS",
    "aggregate",
    "parse_verdicts",
    "notes_from",
    "gateable",
    "confidence_score",
    "report_depth",
]
