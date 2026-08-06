"""Direct execution: in-process, no records or workspaces."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.core import tools as T
from nexhunter.execution.service import ExecutionService


def _service(tmp: Path, cache_enabled: bool = False) -> ExecutionService:
    os.environ["NEXHUNTER_DATA_DIR"] = str(tmp)
    os.environ["NEXHUNTER_CACHE_ENABLED"] = "true" if cache_enabled else "false"
    return ExecutionService()


def _echo_probe():
    """Register a harmless test tool that echoes its argv."""
    T.TOOLS["echo_probe"] = T.ToolSpec(
        name="echo_probe",
        binary=sys.executable,
        description="test-only echo",
        params={"target": None, "note": ""},
        timeout=30,
        risk_level="passive",
        cacheable=False,
        builder=lambda p: [sys.executable, "-c",
                           "import sys; print(' '.join(sys.argv[1:]))",
                           p["target"], p["note"]],
    )


def test_direct_unknown_tool(tmp_path: Path):
    """An unregistered tool never reaches a process on the direct path either."""
    service = _service(tmp_path)
    result = service.run_direct("definitely_not_a_tool", {"target": "example.com"})

    assert not result["ok"]
    assert result["code"] == "UNKNOWN_TOOL"


def test_direct_invalid_params(tmp_path: Path):
    """Typed validation still runs before anything spawns."""
    _echo_probe()
    service = _service(tmp_path)
    try:
        result = service.run_direct("echo_probe", {})
    finally:
        T.TOOLS.pop("echo_probe", None)

    assert not result["ok"]
    assert result["code"] == "INVALID_PARAMS"


def test_direct_returns_output_without_history(tmp_path: Path):
    """Direct runs return output but mint no record, workspace, or process."""
    _echo_probe()
    service = _service(tmp_path)
    try:
        result = service.run_direct("echo_probe",
                                    {"target": "example.com", "note": "hello"})

        assert result["ok"] is True
        assert result["exit"] == 0
        assert "hello" in result["output"]
        assert result["execution_id"] is None
        assert service.registry.list() == [], "direct mode must not mint records"
        assert service.list_processes() == []
    finally:
        T.TOOLS.pop("echo_probe", None)


def test_direct_uses_shared_cache(tmp_path: Path):
    """The ResultCache stays live: a repeat call is served, not re-run."""
    service = _service(tmp_path, cache_enabled=True)

    T.TOOLS["count_probe"] = T.ToolSpec(
        name="count_probe",
        binary=sys.executable,
        description="counts invocations",
        params={"target": None},
        timeout=30,
        risk_level="passive",
        cacheable=True,
        builder=lambda p: [sys.executable, "-c", "print('RUN')"],
    )
    try:
        first = service.run_direct("count_probe", {"target": "example.com"})
        second = service.run_direct("count_probe", {"target": "example.com"})

        assert first["cached"] is False
        assert "RUN" in first["output"]
        assert second["cached"] is True, "repeat call must come from the shared cache"
        assert service.cache.hits >= 1
    finally:
        T.TOOLS.pop("count_probe", None)


def test_direct_non_deterministic_never_cached(tmp_path: Path):
    """Timeout/termination results are facts about a run, not cache entries."""
    service = _service(tmp_path, cache_enabled=True)

    T.TOOLS["sleep_probe"] = T.ToolSpec(
        name="sleep_probe",
        binary=sys.executable,
        description="sleeps past the timeout",
        params={"target": None},
        timeout=1,
        risk_level="passive",
        cacheable=True,
        builder=lambda p: [sys.executable, "-c", "import time; time.sleep(10)"],
    )
    try:
        first = service.run_direct("sleep_probe", {"target": "example.com"})
        second = service.run_direct("sleep_probe", {"target": "example.com"})

        assert first["ok"] is False
        assert first["status"] == "timed_out"
        assert second["cached"] is False, "a timed-out run is never served from cache"
    finally:
        T.TOOLS.pop("sleep_probe", None)


def test_execute_direct_flag_routes_to_fast_path(tmp_path: Path):
    """execute(direct=True) short-circuits into run_direct."""
    _echo_probe()
    service = _service(tmp_path)
    try:
        result = service.execute("echo_probe", {"target": "example.com"}, direct=True)

        assert result["ok"] is True
        assert result["execution_id"] is None
    finally:
        T.TOOLS.pop("echo_probe", None)


def test_async_implies_tracked_path(tmp_path: Path):
    """Async always routes to the tracked path, even with direct requested."""
    _echo_probe()
    service = _service(tmp_path)
    try:
        result = service.execute("echo_probe", {"target": "example.com"},
                                 run_async=True, direct=True)

        assert result["ok"] is True
        assert result["async"] is True
        assert result["execution_id"], "an async run must leave a record to poll"
    finally:
        T.TOOLS.pop("echo_probe", None)


def test_direct_output_redacted(tmp_path: Path):
    """Secrets are still scrubbed from direct output."""
    service = _service(tmp_path)
    T.TOOLS["leak_probe"] = T.ToolSpec(
        name="leak_probe",
        binary=sys.executable,
        description="prints a fake secret",
        params={"target": None},
        timeout=30,
        risk_level="passive",
        cacheable=False,
        builder=lambda p: [sys.executable, "-c", "print('password=supersecret1')"],
    )
    try:
        result = service.run_direct("leak_probe", {"target": "example.com"})

        assert result["ok"] is True
        assert "supersecret1" not in result["output"]
    finally:
        T.TOOLS.pop("leak_probe", None)


def test_tools_run_contract():
    """T.run (legacy Engine path) keeps its result dict contract.

    Locks the shape so the delegation to ProcessRunner (tree-kill on the agent
    path) is a behavior-preserving refactor, not a regression.
    """
    ok = T.run([sys.executable, "-c", "print('hello-world')"], timeout=10)
    assert ok["ok"] is True and ok["exit"] == 0
    assert "hello-world" in ok["stdout"]

    missing = T.run(["nexhunter-not-a-real-binary-xyz"], timeout=5)
    assert missing["ok"] is False and missing["error"]
