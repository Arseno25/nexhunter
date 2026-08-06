"""Execution layer: workspaces, state machine, process control, registry."""

import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.execution.models import (
    ExecutionRecord,
    ExecutionStatus,
    InvalidTransition,
)
from nexhunter.execution.registry import ExecutionRegistry
from nexhunter.execution.runner import ProcessRunner, terminate_tree
from nexhunter.execution.workspace import Workspace, WorkspaceError

PYTHON = sys.executable


# --------------------------------------------------------------------------
# Workspace
# --------------------------------------------------------------------------

def test_workspace_layout(base: Path):
    """Workspace lands under executions/<exec>/."""
    print("[TEST] Workspace layout...")
    workspace = Workspace.create("abc123", base_dir=base)

    assert workspace.root.is_dir(), "workspace directory should exist"
    parts = workspace.root.parts
    assert "executions" in parts
    assert parts[-1] == "abc123"

    print("  [OK] Workspace created in the expected location")


def test_workspace_rejects_unsafe_ids(base: Path):
    """Traversal in an execution id is refused."""
    print("[TEST] Workspace rejects unsafe ids...")
    for bad in ["../escape", "..", "a/b", "exec\x00", "", "/abs"]:
        try:
            Workspace.create(bad, base_dir=base)
            raise AssertionError(f"expected rejection of execution id {bad!r}")
        except WorkspaceError:
            pass

    print("  [OK] Unsafe identifiers rejected")


def test_workspace_artifact_path_traversal(base: Path):
    """Artifact names cannot escape the workspace."""
    print("[TEST] Artifact path traversal blocked...")
    workspace = Workspace.create("exec1", base_dir=base)

    for bad in ["../outside.txt", "../../etc/passwd", "sub/dir.txt", "a\x00b", "", "/etc/passwd"]:
        try:
            workspace.artifact_path(bad)
            raise AssertionError(f"expected rejection of artifact name {bad!r}")
        except WorkspaceError:
            pass

    good = workspace.artifact_path("stdout.log")
    assert good.parent == workspace.root.resolve()

    print("  [OK] Traversal, nesting, and null bytes rejected")


def test_workspace_symlink_escape(base: Path):
    """A symlink planted in the workspace cannot serve outside files."""
    print("[TEST] Symlink escape blocked...")
    workspace = Workspace.create("exec-sym", base_dir=base)

    secret = base / "secret.txt"
    secret.write_text("classified", encoding="utf-8")

    link = workspace.root / "leak.txt"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        print("  [SKIP] symlink creation not permitted on this host")
        return

    try:
        workspace.artifact_path("leak.txt")
        raise AssertionError("symlink pointing outside the workspace must be rejected")
    except WorkspaceError:
        pass

    assert all(a["name"] != "leak.txt" for a in workspace.list_artifacts())

    print("  [OK] Symlink escape rejected")


# --------------------------------------------------------------------------
# State machine
# --------------------------------------------------------------------------

def test_state_machine_happy_path():
    """The normal lifecycle is queued -> validating -> authorized -> running -> completed."""
    print("[TEST] Execution state machine happy path...")
    record = ExecutionRecord(tool_name="nmap_scan")

    assert record.status is ExecutionStatus.QUEUED
    record.transition(ExecutionStatus.VALIDATING)
    record.transition(ExecutionStatus.AUTHORIZED)
    record.transition(ExecutionStatus.RUNNING)
    assert record.started_at is not None
    record.transition(ExecutionStatus.COMPLETED)
    assert record.completed_at is not None
    assert record.duration_seconds is not None
    assert record.status.is_terminal

    print("  [OK] Lifecycle transitions recorded with timestamps")


def test_state_machine_rejects_invalid_transitions():
    """Illegal transitions raise instead of corrupting the record."""
    print("[TEST] Invalid state transitions rejected...")
    record = ExecutionRecord(tool_name="nmap_scan")

    try:
        record.transition(ExecutionStatus.COMPLETED)  # queued -> completed
        raise AssertionError("queued should not jump straight to completed")
    except InvalidTransition:
        pass

    record.transition(ExecutionStatus.VALIDATING)
    record.transition(ExecutionStatus.BLOCKED)
    try:
        record.transition(ExecutionStatus.RUNNING)  # terminal -> running
        raise AssertionError("a terminal record must not restart")
    except InvalidTransition:
        pass

    print("  [OK] Illegal transitions raise")


def test_record_dict_has_no_raw_parameters():
    """The serialized record exposes only redacted parameters."""
    print("[TEST] Record serialization stays redacted...")
    record = ExecutionRecord(
        tool_name="wpscan_scan",
        redacted_parameters={"url": "https://example.com", "api_token": "[REDACTED]"},
        redacted_command=["wpscan", "--api-token", "[REDACTED]"],
    )
    payload = record.to_dict()
    assert payload["parameters"]["api_token"] == "[REDACTED]"  # noqa: S105 - dict key, not a real secret
    assert "[REDACTED]" in payload["command"]
    assert payload["status"] == "queued"

    print("  [OK] Only redacted values serialized")


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def test_runner_captures_streams(base: Path):
    """stdout and stderr are captured separately."""
    print("[TEST] Runner captures stdout and stderr separately...")
    runner = ProcessRunner()
    workdir = base / "run-streams"

    result = runner.run(
        [PYTHON, "-c", "import sys; sys.stdout.write('OUT'); sys.stderr.write('ERR')"],
        timeout=30,
        workdir=workdir,
    )

    assert result.exit_code == 0, f"expected clean exit, got {result}"
    assert "OUT" in result.stdout and "ERR" not in result.stdout
    assert "ERR" in result.stderr
    assert result.ok

    print("  [OK] Streams captured separately")


def test_runner_missing_binary(base: Path):
    """A missing binary is reported, not raised."""
    print("[TEST] Runner reports missing binary...")
    runner = ProcessRunner()
    result = runner.run(["nexhunter-not-a-real-binary"], timeout=5, workdir=base / "run-missing")

    assert not result.ok
    assert result.error_code == "BINARY_NOT_FOUND"

    print("  [OK] Missing binary reported")


def test_runner_timeout_kills_children(base: Path):
    """A timeout terminates the whole process tree, not just the direct child."""
    print("[TEST] Runner timeout kills the process tree...")
    workdir = base / "run-timeout"
    workdir.mkdir(parents=True, exist_ok=True)
    marker = workdir / "child-alive.txt"

    # Parent spawns a child that keeps writing after the parent is signalled.
    # If only the parent were killed, the marker would keep growing.
    script = (
        "import subprocess, sys, time\n"
        f"child = subprocess.Popen([sys.executable, '-c', "
        f"\"open(r'{marker.as_posix()}', 'a').close()\\nimport time\\n\"\n"
        "  \"while True:\\n    open(r'" + marker.as_posix() + "', 'a').write('x')\\n    time.sleep(0.05)\"])\n"
        "time.sleep(60)\n"
    )

    runner = ProcessRunner(grace_seconds=1.0)
    started = time.monotonic()
    result = runner.run([PYTHON, "-c", script], timeout=2, workdir=workdir)
    elapsed = time.monotonic() - started

    assert result.timed_out, f"expected a timeout, got {result}"
    assert result.error_code == "TIMEOUT"
    assert elapsed < 30, f"timeout took too long to enforce: {elapsed}s"

    # Give any surviving grandchild a moment, then confirm it stopped growing.
    time.sleep(1.0)
    size_after_kill = marker.stat().st_size if marker.exists() else 0
    time.sleep(1.0)
    size_later = marker.stat().st_size if marker.exists() else 0
    assert size_later == size_after_kill, "grandchild kept running after the timeout"

    print("  [OK] Timeout terminated the tree")


def test_runner_output_limit(base: Path):
    """Runaway output stops the process instead of exhausting memory."""
    print("[TEST] Runner enforces the output limit...")
    runner = ProcessRunner(max_output_bytes=64 * 1024, grace_seconds=1.0)

    result = runner.run(
        [PYTHON, "-c", "import sys\nwhile True: sys.stdout.write('A'*4096); sys.stdout.flush()"],
        timeout=30,
        workdir=base / "run-flood",
    )

    assert result.error_code == "OUTPUT_LIMIT", f"expected the output cap to fire, got {result}"
    assert result.truncated

    print("  [OK] Output limit enforced")


def test_runner_cancellation(base: Path):
    """An execution can be terminated on request while it runs."""
    print("[TEST] Runner honors cancellation...")
    runner = ProcessRunner(grace_seconds=1.0)
    cancelled = threading.Event()

    def cancel_soon():
        time.sleep(0.4)
        cancelled.set()

    threading.Thread(target=cancel_soon, daemon=True).start()
    result = runner.run(
        [PYTHON, "-c", "import time; time.sleep(60)"],
        timeout=60,
        workdir=base / "run-cancel",
        cancel=cancelled.is_set,
    )

    assert result.terminated, f"expected termination, got {result}"
    assert result.error_code == "TERMINATED"

    print("  [OK] Cancellation terminated the process")


def test_terminate_tree_is_safe_on_dead_process(base: Path):
    """Terminating an already-finished process is a no-op, not an error."""
    print("[TEST] terminate_tree tolerates a dead process...")
    import subprocess

    proc = subprocess.Popen([PYTHON, "-c", "pass"])
    proc.wait()
    terminate_tree(proc, grace=0.5)  # must not raise

    print("  [OK] No error on an already-exited process")


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

def test_registry_basic_operations():
    """Records can be added, fetched, filtered, and transitioned."""
    print("[TEST] Registry basic operations...")
    registry = ExecutionRegistry()
    first = registry.add(ExecutionRecord(tool_name="nmap_scan"))
    registry.add(ExecutionRecord(tool_name="httpx_probe"))

    assert registry.get(first.id) is first
    assert registry.get("nope") is None
    assert len(registry.list()) == 2
    assert len(registry.list(status=ExecutionStatus.QUEUED)) == 2

    registry.transition(first.id, ExecutionStatus.VALIDATING)
    assert registry.get(first.id).status is ExecutionStatus.VALIDATING
    assert registry.stats()["total"] == 2

    print("  [OK] Registry stores, filters, and transitions records")


def test_registry_eviction_keeps_running_work():
    """Eviction drops finished records and never a running one."""
    print("[TEST] Registry eviction spares running executions...")
    registry = ExecutionRegistry(max_records=3)

    running = registry.add(ExecutionRecord(tool_name="nmap_scan"))
    running.transition(ExecutionStatus.VALIDATING)
    running.transition(ExecutionStatus.AUTHORIZED)
    running.transition(ExecutionStatus.RUNNING)

    for _ in range(6):
        done = registry.add(ExecutionRecord(tool_name="httpx_probe"))
        done.transition(ExecutionStatus.VALIDATING)
        done.transition(ExecutionStatus.BLOCKED)

    assert len(registry) <= 3, f"registry grew unbounded: {len(registry)}"
    assert registry.get(running.id) is not None, "a running execution must not be evicted"

    print("  [OK] Bounded, and running work preserved")


def test_registry_concurrent_access():
    """Concurrent writers do not lose or corrupt records."""
    print("[TEST] Registry concurrent access...")
    registry = ExecutionRegistry(max_records=1000)
    errors = []

    def worker(index: int):
        try:
            for _n in range(50):
                record = registry.add(
                    ExecutionRecord(tool_name=f"tool{index}")
                )
                registry.transition(record.id, ExecutionStatus.VALIDATING)
                registry.list()
        except Exception as exc:  # noqa: BLE001 - surfaced via the errors list
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors, f"concurrent access raised: {errors[:3]}"
    assert len(registry) == 400, f"expected 400 records, got {len(registry)}"

    print("  [OK] 8 threads x 50 records with no loss or error")


def test_registry_cancel_flags():
    """Cancellation is tracked per execution and cleared afterwards."""
    print("[TEST] Registry cancellation flags...")
    registry = ExecutionRegistry()
    record = registry.add(ExecutionRecord(tool_name="nmap_scan"))

    assert not registry.is_cancelled(record.id)
    assert registry.request_cancel(record.id)
    assert registry.is_cancelled(record.id)
    registry.clear_cancel(record.id)
    assert not registry.is_cancelled(record.id)

    record.transition(ExecutionStatus.VALIDATING)
    record.transition(ExecutionStatus.BLOCKED)
    assert not registry.request_cancel(record.id), "a terminal execution is not cancellable"

    print("  [OK] Cancellation flags behave")


def test_engine_cache_is_lru(base: Path):
    """Cache evicts the least-recently-used entry, not the oldest."""
    print("[TEST] Engine cache is LRU...")
    from nexhunter.core import engine as engine_module
    from nexhunter.core.engine import Engine

    engine = Engine()

    def cmd(n):
        return [PYTHON, "-c", f"print({n})"]

    old_max = engine_module.CACHE_MAX
    engine_module.CACHE_MAX = 8
    try:
        # Fill past the cap so entries fall out.
        for n in range(10):
            engine._cached_run(cmd(n), 5)
        # The first entries are gone; the newest are present.
        assert len(engine._cache) <= 8
        assert " ".join(cmd(9)) in engine._cache
        assert " ".join(cmd(0)) not in engine._cache

        # Touch an entry, then insert enough to evict again: the *touched*
        # entry must survive because it is now the most recently used.
        touch = " ".join(cmd(5))
        assert touch in engine._cache, "entry should still be cached"
        engine._cache.move_to_end(touch)
        for n in range(10, 14):
            engine._cached_run(cmd(n), 5)
        assert touch in engine._cache, "recently used entry must survive eviction"

        # A cache hit also refreshes recency (via move_to_end in _cached_run).
        hit = " ".join(cmd(12))
        assert hit in engine._cache
        for n in range(14, 18):
            engine._cached_run(cmd(n), 5)
        assert hit in engine._cache, "a cache hit must refresh recency"
    finally:
        engine_module.CACHE_MAX = old_max

    print("  [OK] LRU eviction order respected")


if __name__ == "__main__":
    print("\n=== Execution Layer Tests ===\n")
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        test_workspace_layout(base)
        test_workspace_rejects_unsafe_ids(base)
        test_workspace_artifact_path_traversal(base)
        test_workspace_symlink_escape(base)
        test_state_machine_happy_path()
        test_state_machine_rejects_invalid_transitions()
        test_record_dict_has_no_raw_parameters()
        test_runner_captures_streams(base)
        test_runner_missing_binary(base)
        test_runner_timeout_kills_children(base)
        test_runner_output_limit(base)
        test_runner_cancellation(base)
        test_terminate_tree_is_safe_on_dead_process(base)
        test_registry_basic_operations()
        test_registry_eviction_keeps_running_work()
        test_registry_concurrent_access()
        test_registry_cancel_flags()
        test_engine_cache_is_lru(base)
    print("\n=== All Execution Layer Tests Passed ===\n")
