"""History persistence: findings and executions survive a server restart."""

from pathlib import Path

from nexhunter.execution.models import ExecutionRecord, ExecutionStatus
from nexhunter.execution.registry import ExecutionRegistry
from nexhunter.findings.models import Finding, Severity
from nexhunter.findings.store import FindingStore


def test_history_persists_across_restart(tmp_path: Path):
    findings_path = tmp_path / "findings.json"
    executions_path = tmp_path / "executions.json"

    store = FindingStore(path=findings_path)
    finding = store.add(Finding(
        tool="nmap_scan",
        target="127.0.0.1",
        title="port 22 open",
        severity=Severity.MEDIUM,
        evidence={"port": 22},
    ))

    registry = ExecutionRegistry(path=executions_path)
    record = registry.add(ExecutionRecord(tool_name="ping", target="127.0.0.1"))
    for status in (
        ExecutionStatus.VALIDATING,
        ExecutionStatus.AUTHORIZED,
        ExecutionStatus.RUNNING,
        ExecutionStatus.COMPLETED,
    ):
        registry.transition(record.id, status)

    revived_store = FindingStore(path=findings_path)
    revived_registry = ExecutionRegistry(path=executions_path)

    assert len(revived_store) == 1
    revived = revived_store.list()[0]
    assert revived.fingerprint == finding.fingerprint
    assert revived.severity is Severity.MEDIUM
    assert revived.evidence == {"port": 22}

    revived_record = revived_registry.get(record.id)
    assert revived_record is not None
    assert revived_record.status is ExecutionStatus.COMPLETED
    assert revived_record.tool_name == "ping"
    assert revived_record.redacted_parameters == {}


def test_mid_flight_record_comes_back_failed(tmp_path: Path):
    registry = ExecutionRegistry(path=tmp_path / "executions.json")
    record = registry.add(ExecutionRecord(tool_name="nmap_scan", target="10.0.0.1"))
    for status in (ExecutionStatus.VALIDATING, ExecutionStatus.AUTHORIZED, ExecutionStatus.RUNNING):
        registry.transition(record.id, status)

    revived = ExecutionRegistry(path=tmp_path / "executions.json").get(record.id)
    assert revived is not None
    assert revived.status is ExecutionStatus.FAILED
    assert "server restarted" in (revived.error_message or "")


def test_corrupt_history_starts_empty(tmp_path: Path):
    path = tmp_path / "findings.json"
    path.write_text("{not json", encoding="utf-8")
    store = FindingStore(path=path)
    assert len(store) == 0

    path = tmp_path / "executions.json"
    path.write_text("{not json", encoding="utf-8")
    registry = ExecutionRegistry(path=path)
    assert len(registry) == 0


def test_without_path_stays_in_memory(tmp_path: Path):
    store = FindingStore()
    store.add(Finding(tool="ping", target="127.0.0.1", title="up"))
    assert not (tmp_path / "findings.json").exists()

    registry = ExecutionRegistry()
    registry.add(ExecutionRecord(tool_name="ping", target="127.0.0.1"))
    assert not (tmp_path / "executions.json").exists()
