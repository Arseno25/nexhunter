"""Recovery engine: classification, reduced scope, fallback tools, retry loop."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.execution import recovery as R


def test_classify_error_fingerprints():
    assert R.classify_error("connection refused", 0) is R.ErrorType.NETWORK_UNREACHABLE
    assert R.classify_error("timed out", 0) is R.ErrorType.TIMEOUT
    assert R.classify_error("deadline exceeded") is R.ErrorType.TIMEOUT
    assert R.classify_error("rate limit exceeded", 0) is R.ErrorType.RATE_LIMITED
    assert R.classify_error("permission denied", 0) is R.ErrorType.PERMISSION_DENIED
    assert R.classify_error("command not found", 0) is R.ErrorType.TOOL_NOT_FOUND
    assert R.classify_error("cannot allocate memory", 0) is R.ErrorType.RESOURCE_EXHAUSTED


def test_classify_exit_code_without_text():
    assert R.classify_error("", 1) is R.ErrorType.UNKNOWN
    assert R.classify_error("", 0) is R.ErrorType.UNKNOWN


def test_classify_stdout_also_searched():
    assert R.classify_error("", 0, stdout="rate limit reached") is R.ErrorType.RATE_LIMITED


def test_recovery_plan_keeps_cheapest_first_and_degrades():
    plan = R.recovery_plan(R.ErrorType.TIMEOUT, 0)
    assert plan[0] is R.RecoveryAction.RETRY_WITH_REDUCED_SCOPE
    # After exhausting the first strategy the next one surfaces.
    plan2 = R.recovery_plan(R.ErrorType.TIMEOUT, 1)
    assert R.RecoveryAction.RETRY_WITH_REDUCED_SCOPE not in plan2
    # Empty remaining plan falls back to a human decision.
    plan3 = R.recovery_plan(R.ErrorType.TOOL_NOT_FOUND, 9)
    assert plan3 == [R.RecoveryAction.ESCALATE_TO_HUMAN]


def test_reduced_scope_rewrites_aggression_knobs():
    p = R.reduced_scope_params("nmap_scan", {
        "ports": "1-65535", "timing": "T4", "threads": "40",
    })
    assert p["ports"] == "80,443,22,3389"
    assert p["timing"] == "2"
    assert p["threads"] == "20"

    p2 = R.reduced_scope_params("ffuf_scan", {"threads": "3", "rate": "800"})
    assert p2["threads"] == "1"
    assert p2["rate"] == "200"


def test_alternative_tool_known_groups():
    alt = R.alternative_tool("gobuster_dir")
    assert alt in ("ffuf_scan", "dirsearch", "feroxbuster")
    # A registered alternative is preferred over an unregistered one.
    assert R.alternative_tool("dalfox_xss") in ("nuclei_scan", "xsstrike")
    assert R.alternative_tool("definitely_not_a_tool") is None


def test_backoff_seconds_deterministic_and_capped():
    assert R.backoff_seconds(1) == 1.5
    assert R.backoff_seconds(2) == 3.0
    assert R.backoff_seconds(10) == 30.0


class _FakeService:
    """Fails like a dead target, then recovers via scope reduction."""

    def __init__(self):
        self.calls = []

    def execute(self, tool_name, params, direct=True, no_cache=True):
        self.calls.append((tool_name, dict(params), no_cache))
        if len(self.calls) == 1:
            return {"ok": False, "exit": None, "error": "connection refused",
                    "stderr": "no route to host"}
        if len(self.calls) == 2:
            return {"ok": False, "exit": None, "error": "timed out",
                    "stderr": "", "output": ""}
        return {"ok": True, "exit": 0, "stderr": "", "output": "clean"}


def test_execution_recovery_loop_retries_and_returns_trail():
    svc = _FakeService()
    rec = R.ExecutionRecovery(service=svc, max_attempts=3, use_backoff=False)
    result = rec.execute("nmap_scan", {"target": "127.0.0.1", "ports": "1-65535"})

    assert result["ok"] is True
    assert result["exit"] == 0
    trail = result["recovery"]["trail"]
    assert len(trail) == 2
    assert trail[0]["error_type"] == "network_unreachable"
    assert trail[0]["action"] == "retry_with_backoff"
    assert trail[1]["error_type"] == "timeout"
    assert trail[1]["action"] == "retry_with_reduced_scope"
    assert result["recovery"]["exhausted"] is False
    # A retry always bypasses the cache.
    assert svc.calls[1][2] is True


def test_execution_recovery_exhausts_and_escalates():
    class _AlwaysFail(_FakeService):
        def execute(self, tool_name, params, direct=True, no_cache=True):
            self.calls.append((tool_name, dict(params), no_cache))
            return {"ok": False, "exit": 1, "error": "permission denied",
                    "stderr": "", "output": ""}

    rec = R.ExecutionRecovery(service=_AlwaysFail(), max_attempts=2,
                              use_backoff=False)
    result = rec.execute("nmap_scan", {"target": "x"})
    assert result["ok"] is False
    assert result["recovery"]["exhausted"] is True
    assert result["recovery"]["trail"][-1]["outcome"] in ("exhausted", "escalated")


def test_constructor_requires_service_or_run_fn():
    with pytest.raises(ValueError):
        R.ExecutionRecovery()


def test_run_fn_adapter():
    calls = []

    def run_fn(tool, params):
        calls.append(tool)
        return {"ok": True, "exit": 0, "output": "done"}

    rec = R.ExecutionRecovery(run_fn=run_fn, max_attempts=2, use_backoff=False)
    result = rec.execute("probe", {"target": "example.com"})
    assert result["ok"] and calls == ["probe"]
