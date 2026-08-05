"""Security gate enforcement tests."""

import json
import sys
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.security.enforcement import SecurityGate, risk_level_from_str, _load_engagement
from nexhunter.security.authentication import TokenValidator
from nexhunter.security.audit import AuditLogger
from nexhunter.security.engagement import RiskLevel


def _gate(tmp_path, enforce, token="", engagement_path=None, role="operator"):
    tv = TokenValidator(token=token)
    audit = AuditLogger(path=tmp_path / "audit.jsonl")
    gate = SecurityGate(token_validator=tv, audit_logger=audit, enforce=enforce)
    gate.default_role = gate.default_role  # keep operator default
    if engagement_path:
        gate.engagement = _load_engagement(str(engagement_path))
    return gate, audit


def _write_engagement(tmp_path, targets, risks=("passive", "active")):
    path = tmp_path / "eng.json"
    now = datetime.utcnow()
    path.write_text(json.dumps({
        "id": "eng-1",
        "name": "Test",
        "status": "active",
        "starts_at": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "scope": {"allowed_targets": list(targets), "allowed_risk_levels": list(risks)},
    }), encoding="utf-8")
    return path


def test_dev_mode_allows_valid_token(tmp_path):
    """Test dev mode allows execution and audits it."""
    print("[TEST] Dev mode allows authenticated call...")
    gate, audit = _gate(tmp_path, enforce=False, token="")
    result = gate.authorize_tool(None, "nmap_scan", "10.0.0.5", RiskLevel.ACTIVE, "10.0.0.2")
    assert result.allowed
    assert result.policy.policy_code == "DEV_ALLOWED"
    assert audit.read_records()[-1]["event"] == "policy_decision"
    print("  [OK] Allowed and audited")


def test_bad_token_denied(tmp_path):
    """Test an invalid token is denied even in dev mode."""
    print("[TEST] Invalid token denied...")
    gate, audit = _gate(tmp_path, enforce=False, token="secret-token")
    result = gate.authorize_tool("Bearer wrong", "nmap_scan", "10.0.0.5", RiskLevel.ACTIVE, "10.0.0.9")
    assert not result.allowed
    assert result.policy.policy_code == "AUTH_REQUIRED"
    events = [r["event"] for r in audit.read_records()]
    assert "auth_failure" in events
    print("  [OK] Denied and auth failure recorded")


def test_enforce_requires_engagement(tmp_path):
    """Test enforce mode denies when no engagement is configured."""
    print("[TEST] Enforce mode requires engagement...")
    gate, _ = _gate(tmp_path, enforce=True, token="")
    result = gate.authorize_tool(None, "nmap_scan", "10.0.0.5", RiskLevel.ACTIVE)
    assert not result.allowed
    assert result.policy.policy_code == "ENGAGEMENT_REQUIRED"
    print("  [OK] Denied without engagement")


def test_enforce_scope_violation(tmp_path):
    """Test enforce mode denies an out-of-scope target."""
    print("[TEST] Enforce mode blocks out-of-scope target...")
    eng = _write_engagement(tmp_path, ["10.0.0.0/24"])
    gate, _ = _gate(tmp_path, enforce=True, token="", engagement_path=eng)
    result = gate.authorize_tool(None, "nmap_scan", "8.8.8.8", RiskLevel.ACTIVE)
    assert not result.allowed
    assert result.policy.policy_code == "SCOPE_VIOLATION"
    print("  [OK] Out-of-scope denied")


def test_enforce_in_scope_allowed(tmp_path):
    """Test enforce mode allows an in-scope target with permitted risk."""
    print("[TEST] Enforce mode allows in-scope target...")
    eng = _write_engagement(tmp_path, ["10.0.0.0/24"])
    gate, _ = _gate(tmp_path, enforce=True, token="", engagement_path=eng)
    result = gate.authorize_tool(None, "nmap_scan", "10.0.0.5", RiskLevel.ACTIVE)
    assert result.allowed, result.policy.reason
    print("  [OK] In-scope allowed")


def test_enforce_dangerous_tool_needs_approval(tmp_path):
    """Test a dangerous tool is denied pending approval even in scope."""
    print("[TEST] Enforce mode blocks dangerous tool...")
    eng = _write_engagement(tmp_path, ["10.0.0.0/24"], risks=("passive", "active", "intrusive"))
    gate, _ = _gate(tmp_path, enforce=True, token="", engagement_path=eng)
    result = gate.authorize_tool(None, "hydra_attack", "10.0.0.5", RiskLevel.INTRUSIVE)
    assert not result.allowed
    assert result.policy.requires_approval
    assert result.policy.policy_code == "APPROVAL_REQUIRED"
    print("  [OK] Dangerous tool held for approval")


def test_risk_level_from_str_defaults_active():
    """Test unknown risk strings fall back to ACTIVE."""
    print("[TEST] risk_level_from_str default...")
    assert risk_level_from_str("passive") == RiskLevel.PASSIVE
    assert risk_level_from_str("nonsense") == RiskLevel.ACTIVE
    print("  [OK] Defaults to active")


if __name__ == "__main__":
    import tempfile

    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            import inspect
            if inspect.signature(fn).parameters:
                with tempfile.TemporaryDirectory() as d:
                    fn(Path(d))
            else:
                fn()
    print("\nAll enforcement tests passed")
