"""Offensive agents are gated: not runnable via /api/agents unless enabled.

The /api/agents route runs an agent directly, outside the ExecutionService gate
and its risk ceiling. The exploit_kit agents take attack-side actions, so they
must be refused there unless intrusive tooling is explicitly turned on.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.agents import AGENTS
from nexhunter.api import server


OFFENSIVE = ("rangefinder", "fireworks", "switchblade", "cve_smith",
             "ghost_wright", "autopilot", "blitzplan", "warroom")


def _clear_flag():
    os.environ.pop("NEXHUNTER_INTRUSIVE_TOOLS_ENABLED", None)


def test_exploit_kit_agents_are_flagged_offensive():
    """Every registered exploit_kit agent carries offensive=True."""
    print("[TEST] exploit_kit agents flagged offensive...")
    present = [n for n in OFFENSIVE if n in AGENTS]
    assert present, "expected some exploit_kit agents registered"
    for name in present:
        assert getattr(AGENTS[name], "offensive", False) is True, name
    print(f"  [OK] {len(present)} offensive agents flagged")


def test_offensive_blocked_by_default():
    """Without the intrusive flag, an offensive agent is refused."""
    print("[TEST] offensive blocked by default...")
    _clear_flag()
    present = [n for n in OFFENSIVE if n in AGENTS]
    for name in present:
        assert server.offensive_agent_blocked(name) is True, name
    print("  [OK] Offensive agents blocked when intrusive is off")


def test_offensive_allowed_when_intrusive_enabled():
    """With the flag on, the gate opens."""
    print("[TEST] offensive allowed when enabled...")
    os.environ["NEXHUNTER_INTRUSIVE_TOOLS_ENABLED"] = "true"
    try:
        present = [n for n in OFFENSIVE if n in AGENTS]
        for name in present:
            assert server.offensive_agent_blocked(name) is False, name
    finally:
        _clear_flag()
    print("  [OK] Gate opens with NEXHUNTER_INTRUSIVE_TOOLS_ENABLED")


def test_benign_agent_never_blocked():
    """A normal observation agent is never gated."""
    print("[TEST] benign agent not gated...")
    _clear_flag()
    for name in ("browser", "technology", "decision"):
        if name in AGENTS:
            assert server.offensive_agent_blocked(name) is False, name
    print("  [OK] Benign agents run freely")


if __name__ == "__main__":
    print("\n=== Offensive Agent Gate Tests ===\n")
    test_exploit_kit_agents_are_flagged_offensive()
    test_offensive_blocked_by_default()
    test_offensive_allowed_when_intrusive_enabled()
    test_benign_agent_never_blocked()
    print("\n=== All Agent Gate Tests Passed ===\n")
