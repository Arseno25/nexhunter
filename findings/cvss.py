"""CVSS 3.1 base score calculator.

Pure arithmetic over a vector string -- the official FIRST.org formula, no
judgment involved. This is deliberately separate from *deciding* a finding is
exploitable (see gates.py): a vector is an input someone (human or AI) already
assessed, and this module only computes what that assessment is worth as a
number. A malformed vector is refused, never guessed at.
"""

import math
from dataclasses import dataclass

_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_S = {"U", "C"}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_METRIC_VALUES = {"AV": _AV, "AC": _AC, "UI": _UI, "C": _CIA, "I": _CIA, "A": _CIA}


@dataclass(frozen=True)
class CVSSResult:
    vector: str
    base_score: float
    severity: str  # Severity.value


def _parse(vector: str) -> dict[str, str]:
    text = (vector or "").strip()
    if not text.upper().startswith("CVSS:3.1/"):
        raise ValueError("vector must start with 'CVSS:3.1/'")

    metrics: dict[str, str] = {}
    for part in text[len("CVSS:3.1/"):].split("/"):
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"malformed metric segment: {part!r}")
        key, value = part.split(":", 1)
        metrics[key.upper()] = value.upper()

    missing = [m for m in _METRIC_ORDER if m not in metrics]
    if missing:
        raise ValueError(f"missing required metric(s): {', '.join(missing)}")
    extra = set(metrics) - set(_METRIC_ORDER)
    if extra:
        raise ValueError(f"unknown metric(s): {', '.join(sorted(extra))}")

    if metrics["S"] not in _S:
        raise ValueError(f"S must be one of {sorted(_S)}, got {metrics['S']!r}")
    for key, table in _METRIC_VALUES.items():
        if metrics[key] not in table:
            raise ValueError(f"{key} must be one of {sorted(table)}, got {metrics[key]!r}")
    pr_table = _PR_CHANGED if metrics["S"] == "C" else _PR_UNCHANGED
    if metrics["PR"] not in pr_table:
        raise ValueError(f"PR must be one of {sorted(pr_table)}, got {metrics['PR']!r}")

    return metrics


def _roundup(value: float) -> float:
    """CVSS spec's roundup: round to the nearest 0.1, always upward.

    Done in integer space (value scaled by 100000) to avoid the float
    precision errors a naive `ceil(value * 10) / 10` runs into.
    """
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000.0
    return (math.floor(int_value / 10000) + 1) / 10.0


def score_vector(vector: str) -> CVSSResult:
    """Compute the CVSS 3.1 base score from a full vector string.

    Raises ValueError with a specific reason on anything malformed -- an
    invalid metric, a missing one, or a value not on that metric's scale.
    """
    # Deferred: models.py imports this module for try_score_vector(), so a
    # top-level import here would be circular.
    from nexhunter.findings.models import severity_from_cvss

    m = _parse(vector)
    scope_changed = m["S"] == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED

    av = _AV[m["AV"]]
    ac = _AC[m["AC"]]
    pr = pr_table[m["PR"]]
    ui = _UI[m["UI"]]
    c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    elif scope_changed:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        base_score = _roundup(min(impact + exploitability, 10.0))

    normalized_vector = "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in _METRIC_ORDER)
    return CVSSResult(
        vector=normalized_vector,
        base_score=base_score,
        severity=severity_from_cvss(base_score).value,
    )


def try_score_vector(vector: str) -> CVSSResult | None:
    """Same as score_vector, but None instead of raising -- for call sites
    that record a best-effort value rather than reject a whole finding over
    one bad field (see Finding.__post_init__, which drops rather than fails
    on a malformed cve_id/cwe_id the same way)."""
    try:
        return score_vector(vector)
    except ValueError:
        return None


__all__ = ["CVSSResult", "score_vector", "try_score_vector"]
