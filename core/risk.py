"""Risk classification of registered tools.

A pure label used for metadata and autonomous-mode planning (which tools an
orchestrator auto-runs vs. surfaces for a human). It enforces nothing on its
own -- there is no policy engine in front of execution.
"""

from enum import Enum


class RiskLevel(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"
    DESTRUCTIVE = "destructive"


def risk_level_from_str(value: str) -> RiskLevel:
    """Map a tool's risk string to the RiskLevel enum (defaults to ACTIVE)."""
    try:
        return RiskLevel(value)
    except ValueError:
        return RiskLevel.ACTIVE
