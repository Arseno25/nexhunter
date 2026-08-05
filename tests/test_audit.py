"""Audit logging tests."""

import json
import sys
import threading
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.security.audit import AuditLogger
from nexhunter.security.authorization import AuthContext, ROLES
from nexhunter.security.engagement import Engagement, EngagementScope, RiskLevel
from nexhunter.security.policy import PolicyEngine


def _context(role="tester"):
    return AuthContext(
        identity="analyst@example.com",
        role=ROLES[role],
        source_ip="10.0.0.2",
        request_id="req-1",
    )


def _engagement():
    return Engagement(
        id="eng-001",
        name="Test engagement",
        status="active",
        scope=EngagementScope(
            allowed_targets=["10.0.0.0/24"],
            allowed_risk_levels=[RiskLevel.PASSIVE, RiskLevel.ACTIVE],
        ),
        starts_at=datetime.utcnow() - timedelta(hours=1),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )


def test_audit_writes_jsonl(tmp_path):
    """Test each record is one parseable JSON line."""
    print("[TEST] Audit writes JSONL...")
    logger = AuditLogger(path=tmp_path / "audit.jsonl")
    logger.log("test_event", tool="nmap")
    logger.log("test_event", tool="httpx")

    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    for line in lines:
        record = json.loads(line)
        assert record["event"] == "test_event"
        assert "ts" in record
    print("  [OK] Two JSONL records written")


def test_audit_records_denied_decision(tmp_path):
    """Test a denied policy decision is recorded with its policy code."""
    print("[TEST] Audit records denied policy decision...")
    logger = AuditLogger(path=tmp_path / "audit.jsonl")
    engine = PolicyEngine()
    ctx, eng = _context(), _engagement()

    policy = engine.check_execution(ctx, eng, "nmap", "8.8.8.8", RiskLevel.ACTIVE)
    assert not policy.is_allowed
    logger.log_policy_decision(ctx, eng, "nmap", "8.8.8.8", RiskLevel.ACTIVE, policy)

    record = logger.read_records()[-1]
    assert record["decision"] == "denied"
    assert record["policy_code"] == "SCOPE_VIOLATION"
    assert record["identity"] == "analyst@example.com"
    assert record["engagement_id"] == "eng-001"
    assert record["target"] == "8.8.8.8"
    print("  [OK] Denial recorded with identity and policy code")


def test_audit_records_allowed_decision(tmp_path):
    """Test an allowed policy decision is recorded."""
    print("[TEST] Audit records allowed policy decision...")
    logger = AuditLogger(path=tmp_path / "audit.jsonl")
    engine = PolicyEngine()
    ctx, eng = _context(), _engagement()

    policy = engine.check_execution(ctx, eng, "nmap", "10.0.0.5", RiskLevel.ACTIVE)
    assert policy.is_allowed, policy.reason
    logger.log_policy_decision(ctx, eng, "nmap", "10.0.0.5", RiskLevel.ACTIVE, policy)

    record = logger.read_records()[-1]
    assert record["decision"] == "allowed"
    assert record["risk"] == "active"
    print("  [OK] Allowed decision recorded")


def test_audit_preserves_identity(tmp_path):
    """Test identity is never redacted - the trail must record who acted."""
    print("[TEST] Audit preserves identity...")
    logger = AuditLogger(path=tmp_path / "audit.jsonl")
    logger.log_auth_failure(source_ip="10.0.0.9", reason="invalid token")
    logger.log_execution(_context(), _engagement(), "nmap", "10.0.0.5")

    record = logger.read_records()[-1]
    assert record["identity"] == "analyst@example.com"
    print("  [OK] Identity intact")


def test_audit_redacts_command_secrets(tmp_path):
    """Test secrets in executed commands are redacted before writing."""
    print("[TEST] Audit redacts command secrets...")
    logger = AuditLogger(path=tmp_path / "audit.jsonl")
    logger.log_execution(
        _context(),
        _engagement(),
        "hydra",
        "10.0.0.5",
        command=["hydra", "-l", "admin", "-p", "letmein", "10.0.0.5"],
    )

    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "letmein" not in raw
    assert "hydra" in raw
    print("  [OK] Command secret redacted on disk")


def test_audit_concurrent_writes(tmp_path):
    """Test concurrent writes do not interleave or lose records."""
    print("[TEST] Audit is thread-safe...")
    logger = AuditLogger(path=tmp_path / "audit.jsonl")

    def worker(n):
        for i in range(20):
            logger.log("concurrent", worker=n, seq=i)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    records = logger.read_records()
    assert len(records) == 100, f"expected 100 records, got {len(records)}"
    print("  [OK] 100 records, none lost or corrupted")


def test_audit_read_missing_file(tmp_path):
    """Test reading before any write returns empty."""
    print("[TEST] Audit read on empty log...")
    logger = AuditLogger(path=tmp_path / "nested" / "audit.jsonl")
    assert logger.read_records() == []
    print("  [OK] Empty log reads as []")


if __name__ == "__main__":
    import tempfile

    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            with tempfile.TemporaryDirectory() as d:
                fn(Path(d))
    print("\nAll audit tests passed")
