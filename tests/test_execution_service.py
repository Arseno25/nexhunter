"""ExecutionService: the shared path REST and MCP both go through."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.core import tools as T
from nexhunter.execution.models import ExecutionStatus
from nexhunter.execution.service import ExecutionService


def _service(tmp: Path) -> ExecutionService:
    os.environ["NEXHUNTER_DATA_DIR"] = str(tmp)
    return ExecutionService()


def test_unknown_tool_rejected(tmp: Path):
    """An unregistered tool name never reaches a process."""
    print("[TEST] Unknown tool rejected...")
    service = _service(tmp)
    result = service.execute("definitely_not_a_tool", {"target": "example.com"})

    assert not result["ok"]
    assert result["code"] == "UNKNOWN_TOOL"

    print("  [OK] Unknown tool rejected")


def test_missing_required_param_blocks(tmp: Path):
    """A missing required parameter blocks before any command is built."""
    print("[TEST] Missing required parameter blocked...")
    service = _service(tmp)
    result = service.execute("nmap_scan", {})  # target is required

    assert not result["ok"]
    assert result["code"] == "INVALID_PARAMS"

    record = service.registry.get(result["execution_id"])
    assert record.status is ExecutionStatus.BLOCKED
    assert record.started_at is None, "a blocked execution must never have started"

    print("  [OK] Blocked before execution")


def test_successful_execution_records_workspace(tmp: Path):
    """An execution runs, records output, and gets its own workspace."""
    print("[TEST] Successful execution end to end...")
    service = _service(tmp)

    # Register a harmless tool so the test never depends on an installed scanner.
    T.TOOLS["echo_probe"] = T.ToolSpec(
        name="echo_probe",
        binary=sys.executable,
        description="test-only echo",
        params={"target": None},
        timeout=30,
        risk_level="passive",
        builder=lambda p: [sys.executable, "-c", f"print({p['target']!r})"],
    )
    try:
        result = service.execute("echo_probe", {"target": "example.com"})

        assert result["ok"], f"expected success, got {result}"
        assert "example.com" in result["output"]

        record = service.registry.get(result["execution_id"])
        assert record.status is ExecutionStatus.COMPLETED
        assert record.exit_code == 0
        assert record.duration_seconds is not None

        workspace = Path(record.workspace_path)
        assert workspace.is_dir(), "execution should have its own workspace"
        assert record.id in workspace.parts, "workspace must be keyed by execution id"
        assert (workspace / "stdout.log").exists(), "raw stdout kept as an artifact"

        artifacts = service.artifacts(record.id)["artifacts"]
        assert any(a["name"] == "stdout.log" for a in artifacts)
    finally:
        T.TOOLS.pop("echo_probe", None)

    print("  [OK] Ran, recorded, and isolated in a workspace")


def test_executions_get_separate_workspaces(tmp: Path):
    """Two executions of the same tool do not share a directory."""
    print("[TEST] Workspaces are per execution...")
    service = _service(tmp)

    T.TOOLS["echo_probe"] = T.ToolSpec(
        name="echo_probe",
        binary=sys.executable,
        description="test-only echo",
        params={"target": None},
        timeout=30,
        risk_level="passive",
        builder=lambda p: [sys.executable, "-c", "print('hi')"],
    )
    try:
        first = service.execute("echo_probe", {"target": "a.example.com"})
        second = service.execute("echo_probe", {"target": "b.example.com"})

        path_a = service.registry.get(first["execution_id"]).workspace_path
        path_b = service.registry.get(second["execution_id"]).workspace_path
        assert path_a != path_b, "executions must not share a workspace"
    finally:
        T.TOOLS.pop("echo_probe", None)

    print("  [OK] Separate workspaces per execution")


def test_secrets_redacted_in_record(tmp: Path):
    """Credentials in parameters never land in the stored record."""
    print("[TEST] Secrets redacted in the execution record...")
    service = _service(tmp)

    result = service.execute("wpscan_scan", {"url": "https://example.com", "api_token": "s3cr3t-value"})
    record = service.registry.get(result["execution_id"])

    stored = str(record.to_dict())
    assert "s3cr3t-value" not in stored, "the raw token must not be stored"
    assert record.redacted_parameters.get("api_token") == "[REDACTED]"

    print("  [OK] Token redacted in the record")


def test_terminate_unknown_execution(tmp: Path):
    """Terminating an unknown id is an error, not a crash."""
    print("[TEST] Terminate unknown execution...")
    service = _service(tmp)
    result = service.terminate("does-not-exist")

    assert not result["ok"]
    assert result["code"] == "NOT_FOUND"

    print("  [OK] Unknown execution reported")


if __name__ == "__main__":
    print("\n=== Execution Service Tests ===\n")
    previous_data_dir = os.environ.get("NEXHUNTER_DATA_DIR")
    try:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            test_unknown_tool_rejected(tmp)
            test_missing_required_param_blocks(tmp)
            test_successful_execution_records_workspace(tmp)
            test_executions_get_separate_workspaces(tmp)
            test_secrets_redacted_in_record(tmp)
            test_terminate_unknown_execution(tmp)
    finally:
        if previous_data_dir is None:
            os.environ.pop("NEXHUNTER_DATA_DIR", None)
        else:
            os.environ["NEXHUNTER_DATA_DIR"] = previous_data_dir
    print("\n=== All Execution Service Tests Passed ===\n")
