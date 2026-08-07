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
"""

from enum import Enum


class GateVerdict(str, Enum):
    PASS = "pass"      # noqa: S105 - a gate verdict, not a hardcoded credential
    FAIL = "fail"       # gate not satisfied -- the finding is refuted here
    UNSURE = "unsure"   # evidence does not clearly settle this gate

    @staticmethod
    def parse(value) -> "GateVerdict":
        text = str(value or "").strip().lower()
        for candidate in GateVerdict:
            if candidate.value == text:
                return candidate
        raise ValueError(f"gate verdict must be one of {[v.value for v in GateVerdict]}, got {value!r}")


class GateStatus(str, Enum):
    UNREVIEWED = "unreviewed"      # no gate verdicts submitted yet
    CONFIRMED = "confirmed"        # all four gates passed
    REFUTED = "refuted"            # at least one gate failed
    NEEDS_REVIEW = "needs_review"  # no failures, but at least one UNSURE


GATE_NAMES: tuple[str, ...] = ("refutation", "reachability", "trigger", "impact")


def aggregate(verdicts: dict[str, GateVerdict]) -> GateStatus:
    """Roll up four per-gate verdicts into one status.

    A single FAIL refutes the finding outright, regardless of the others --
    matches the gate's own definition: "fail any gate -> rejected". Any
    remaining UNSURE (with no FAIL) means a human/AI has to look closer.
    """
    values = [verdicts[name] for name in GATE_NAMES]
    if any(v == GateVerdict.FAIL for v in values):
        return GateStatus.REFUTED
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


__all__ = [
    "GateVerdict",
    "GateStatus",
    "GATE_NAMES",
    "aggregate",
    "parse_verdicts",
    "notes_from",
    "gateable",
]
