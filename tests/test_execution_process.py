"""Granular process management on the single execution path."""

import os
import sys
import time
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.core import tools as T
from nexhunter.execution.models import ExecutionStatus
from nexhunter.execution.service import ExecutionService


def _service(tmp: Path) -> ExecutionService:
    os.environ["NEXHUNTER_DATA_DIR"] = str(tmp)
    return ExecutionService()


def _register_sleeper(name: str, seconds: float = 5.0) -> None:
    T.TOOLS[name] = T.ToolSpec(
        name=name,
        binary=sys.executable,
        description="test-only sleeper",
        params={"target": None},
        timeout=30,
        risk_level="passive",
        cacheable=False,  # a live process must not be short-circuited by cache
        builder=lambda p: [sys.executable, "-c", f"import time; time.sleep({seconds})"],
    )


def _wait_running(service: ExecutionService, execution_id: str, deadline: float = 5.0):
    """Poll until the execution has a pid and is RUNNING."""
    end = time.time() + deadline
    while time.time() < end:
        record = service.registry.get(execution_id)
        if record and record.status is ExecutionStatus.RUNNING and record.pid:
            return record
        time.sleep(0.02)
    return service.registry.get(execution_id)


def _wait_terminal(service: ExecutionService, execution_id: str, deadline: float = 8.0):
    end = time.time() + deadline
    while time.time() < end:
        record = service.registry.get(execution_id)
        if record and record.status.is_terminal:
            return record
        time.sleep(0.02)
    return service.registry.get(execution_id)


def test_running_execution_is_a_live_process(tmp: Path):
    """An async run shows up in list_processes with a live pid."""
    print("[TEST] Live process listing...")
    service = _service(tmp)
    _register_sleeper("sleeper_list")
    try:
        started = service.execute("sleeper_list", {"target": "x"}, run_async=True)
        record = _wait_running(service, started["execution_id"])
        assert record.status is ExecutionStatus.RUNNING and record.pid

        procs = service.list_processes()
        assert any(p["execution_id"] == record.id and p["pid"] == record.pid for p in procs)

        # Status resolvable by both pid and execution id.
        by_pid = service.process_status(record.pid)
        by_id = service.process_status(record.id)
        assert by_pid["ok"] and by_id["ok"]
        assert by_pid["execution_id"] == record.id

        service.terminate_process(record.pid)
        _wait_terminal(service, record.id)
    finally:
        service.terminate(started["execution_id"])
        T.TOOLS.pop("sleeper_list", None)
    print("  [OK] Running execution visible as a live process")


def test_terminate_by_pid_goes_through_state_machine(tmp: Path):
    """Killing by pid records the cancel and lands in TERMINATED, not a raw kill."""
    print("[TEST] Terminate by pid...")
    service = _service(tmp)
    _register_sleeper("sleeper_kill")
    try:
        started = service.execute("sleeper_kill", {"target": "x"}, run_async=True)
        record = _wait_running(service, started["execution_id"])

        result = service.terminate_process(record.pid)
        assert result["ok"], result

        final = _wait_terminal(service, record.id)
        assert final.status is ExecutionStatus.TERMINATED, final.status
        assert service.list_processes() == [], "no live process after termination"
    finally:
        T.TOOLS.pop("sleeper_kill", None)
    print("  [OK] Terminate by pid transitions to TERMINATED")


def test_unknown_process_reported(tmp: Path):
    """Status and terminate on an unknown pid are errors, not crashes."""
    print("[TEST] Unknown process...")
    service = _service(tmp)
    assert service.process_status(999999)["code"] == "NOT_FOUND"
    assert service.terminate_process(999999)["code"] == "NOT_FOUND"
    assert service.list_processes() == []
    print("  [OK] Unknown pid reported cleanly")


if __name__ == "__main__":
    print("\n=== Process Management Tests ===\n")
    previous = os.environ.get("NEXHUNTER_DATA_DIR")
    try:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            test_running_execution_is_a_live_process(tmp)
            test_terminate_by_pid_goes_through_state_machine(tmp)
            test_unknown_process_reported(tmp)
    finally:
        if previous is None:
            os.environ.pop("NEXHUNTER_DATA_DIR", None)
        else:
            os.environ["NEXHUNTER_DATA_DIR"] = previous
    print("\n=== All Process Management Tests Passed ===\n")
