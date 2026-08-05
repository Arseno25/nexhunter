"""Engagement storage, resolution, and enforce-by-default behavior."""

import json
import os
import sys
import threading
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.engagements.store import (
    EngagementError,
    EngagementStore,
    engagement_from_dict,
    engagement_to_dict,
    validate,
)
from nexhunter.execution.service import ExecutionService
from nexhunter.security.authentication import TokenValidator
from nexhunter.security.enforcement import SecurityGate, _default_enforce
from nexhunter.security.engagement import RiskLevel


def _payload(**overrides) -> dict:
    now = datetime.utcnow()
    payload = {
        "id": "ENG-001",
        "name": "Example Assessment",
        "status": "active",
        "starts_at": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(days=30)).isoformat(),
        "scope": {
            "allowed_targets": ["example.com", "*.example.com"],
            "denied_targets": ["admin.example.com"],
            "allowed_risk_levels": ["passive", "active"],
        },
    }
    payload.update(overrides)
    return payload


# --------------------------------------------------------------------------
# Parsing and validation
# --------------------------------------------------------------------------

def test_roundtrip_preserves_scope():
    """Serializing and reparsing an engagement does not change its scope."""
    print("[TEST] Engagement round-trip...")
    original = engagement_from_dict(_payload())
    reparsed = engagement_from_dict(engagement_to_dict(original))

    assert reparsed.id == original.id
    assert reparsed.scope.allowed_targets == original.scope.allowed_targets
    assert reparsed.scope.denied_targets == original.scope.denied_targets
    assert reparsed.scope.allowed_risk_levels == original.scope.allowed_risk_levels
    assert reparsed.starts_at == original.starts_at
    print("  [OK] Scope survives a round-trip")


def test_invalid_ids_rejected():
    """An id that could traverse a path is refused."""
    print("[TEST] Invalid engagement ids rejected...")
    for bad in ["../escape", "a/b", "", "..", "eng id", "x" * 200]:
        try:
            engagement_from_dict(_payload(id=bad))
            assert False, f"expected rejection of id {bad!r}"
        except EngagementError:
            pass
    print("  [OK] Traversing and malformed ids rejected")


def test_destructive_risk_cannot_be_granted():
    """A scope file cannot hand out destructive risk."""
    print("[TEST] Destructive risk not grantable by definition...")
    try:
        engagement_from_dict(_payload(scope={
            "allowed_targets": ["example.com"],
            "allowed_risk_levels": ["passive", "destructive"],
        }))
        assert False, "destructive risk must not be grantable through an engagement"
    except EngagementError as exc:
        assert "destructive" in str(exc).lower()
    print("  [OK] Destructive risk refused")


def test_bad_dates_rejected():
    """Malformed or inverted validity windows are refused."""
    print("[TEST] Bad validity windows rejected...")
    try:
        engagement_from_dict(_payload(starts_at="not-a-date"))
        assert False, "expected rejection of an unparseable date"
    except EngagementError:
        pass

    now = datetime.utcnow()
    try:
        engagement_from_dict(_payload(
            starts_at=now.isoformat(),
            expires_at=(now - timedelta(days=1)).isoformat(),
        ))
        assert False, "expected rejection of expires_at before starts_at"
    except EngagementError:
        pass
    print("  [OK] Bad windows rejected")


def test_empty_allowlist_fails_validation():
    """An engagement that authorizes nothing does not validate."""
    print("[TEST] Empty allow-list fails validation...")
    engagement = engagement_from_dict(_payload(scope={
        "allowed_targets": [],
        "allowed_risk_levels": ["passive"],
    }))
    result = validate(engagement)

    assert not result.ok
    assert any("empty" in e for e in result.errors)
    print("  [OK] Empty allow-list rejected")


# --------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------

def test_store_persists_across_instances(tmp: Path):
    """An engagement written by one store is readable by the next.

    This is the point of storing them: a restart must not drop the scope an
    operator configured.
    """
    print("[TEST] Engagements persist across restarts...")
    EngagementStore(base_dir=tmp).create(_payload())

    reopened = EngagementStore(base_dir=tmp)
    engagement = reopened.get("ENG-001")

    assert engagement is not None, "engagement should survive a new store instance"
    assert engagement.scope.allowed_targets == ["example.com", "*.example.com"]
    print("  [OK] Persisted and reloaded")


def test_store_rejects_duplicate_without_overwrite(tmp: Path):
    """Creating over an existing engagement needs an explicit overwrite."""
    print("[TEST] Duplicate creation refused...")
    store = EngagementStore(base_dir=tmp)
    store.create(_payload())

    try:
        store.create(_payload())
        assert False, "expected a duplicate to be refused"
    except EngagementError as exc:
        assert "already exists" in str(exc)

    store.create(_payload(name="Renamed"), overwrite=True)
    assert store.get("ENG-001").name == "Renamed"
    print("  [OK] Duplicate refused, overwrite honored")


def test_store_rejects_invalid_engagement(tmp: Path):
    """An invalid engagement is never written to disk."""
    print("[TEST] Invalid engagement not persisted...")
    store = EngagementStore(base_dir=tmp)

    try:
        store.create(_payload(scope={"allowed_targets": [], "allowed_risk_levels": ["passive"]}))
        assert False, "expected validation to reject this"
    except EngagementError:
        pass

    assert store.get("ENG-001") is None, "an invalid engagement must not be stored"
    print("  [OK] Invalid engagement not written")


def test_store_skips_corrupt_file(tmp: Path):
    """A corrupt engagement file is skipped, not treated as authorization."""
    print("[TEST] Corrupt engagement file skipped...")
    store = EngagementStore(base_dir=tmp)
    store.create(_payload())
    store.create(_payload(id="ENG-002"))

    corrupt = store.root / "ENG-002" / "engagement.json"
    corrupt.write_text("{ this is not json", encoding="utf-8")

    reopened = EngagementStore(base_dir=tmp)
    assert reopened.get("ENG-001") is not None, "the valid engagement should still load"
    assert reopened.get("ENG-002") is None, "a corrupt engagement must not authorize anything"
    print("  [OK] Corrupt file skipped, valid one intact")


def test_store_status_changes(tmp: Path):
    """Pausing an engagement makes it inactive."""
    print("[TEST] Engagement status changes...")
    store = EngagementStore(base_dir=tmp)
    store.create(_payload())
    assert store.get("ENG-001").is_active()

    store.set_status("ENG-001", "paused")
    assert not store.get("ENG-001").is_active(), "a paused engagement must not be active"

    store.set_status("ENG-001", "active")
    assert store.get("ENG-001").is_active()
    print("  [OK] Status changes take effect")


def test_store_concurrent_creates(tmp: Path):
    """Concurrent writers do not corrupt or lose engagements."""
    print("[TEST] Store concurrent access...")
    store = EngagementStore(base_dir=tmp)
    errors = []

    def worker(index: int):
        try:
            for n in range(10):
                store.create(_payload(id=f"ENG-{index}-{n}"))
                store.list()
        except Exception as exc:  # noqa: BLE001 - surfaced via errors
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors, f"concurrent creation raised: {errors[:3]}"
    assert len(store.list()) == 60, f"expected 60 engagements, got {len(store.list())}"
    print("  [OK] 6 threads x 10 engagements with no loss")


def test_default_engagement_only_when_unambiguous(tmp: Path):
    """A single active engagement is inferred; two are not guessed between."""
    print("[TEST] Default engagement requires no ambiguity...")
    store = EngagementStore(base_dir=tmp)

    assert store.default_engagement() is None, "no engagements means no default"

    store.create(_payload())
    assert store.default_engagement().id == "ENG-001"

    store.create(_payload(id="ENG-002"))
    assert store.default_engagement() is None, "two active engagements must not be guessed between"

    store.set_status("ENG-002", "completed")
    assert store.default_engagement().id == "ENG-001", "one active again means it can be inferred"
    print("  [OK] Ambiguity never guessed at")


# --------------------------------------------------------------------------
# Enforcement
# --------------------------------------------------------------------------

def test_enforcement_defaults_on():
    """Enforcement is on unless explicitly disabled."""
    print("[TEST] Enforcement defaults on...")
    previous = os.environ.pop("NEXHUNTER_ENFORCE", None)
    try:
        assert _default_enforce() is True, "an unset NEXHUNTER_ENFORCE must mean enforced"

        os.environ["NEXHUNTER_ENFORCE"] = "false"
        assert _default_enforce() is False, "an explicit false must disable enforcement"

        os.environ["NEXHUNTER_ENFORCE"] = "true"
        assert _default_enforce() is True
    finally:
        os.environ.pop("NEXHUNTER_ENFORCE", None)
        if previous is not None:
            os.environ["NEXHUNTER_ENFORCE"] = previous
    print("  [OK] Secure by default")


def test_fresh_install_denies_with_a_useful_message(tmp: Path):
    """With enforcement on and no engagement, execution is denied and says why."""
    print("[TEST] Fresh install denies with guidance...")
    store = EngagementStore(base_dir=tmp)
    gate = SecurityGate(
        token_validator=TokenValidator(token=""),
        enforce=True,
        engagement_store=store,
    )
    service = ExecutionService(gate=gate)

    result = service.execute("nmap_scan", {"target": "example.com"})

    assert not result["ok"], "no engagement must deny"
    assert result["code"] == "ENGAGEMENT_REQUIRED"
    assert "create" in result["error"].lower(), (
        f"the denial should tell the operator what to do, got: {result['error']}"
    )
    print("  [OK] Denied, with a message that says how to fix it")


def test_in_scope_execution_allowed_after_creating_engagement(tmp: Path):
    """Creating an engagement is enough to make an in-scope tool run."""
    print("[TEST] Engagement enables in-scope execution...")
    store = EngagementStore(base_dir=tmp)
    store.create(_payload(scope={
        "allowed_targets": ["example.com"],
        "allowed_risk_levels": ["passive", "active"],
    }))
    gate = SecurityGate(
        token_validator=TokenValidator(token=""),
        enforce=True,
        engagement_store=store,
    )

    from nexhunter.security.engagement import TargetValidator
    import ipaddress

    previous_resolver = TargetValidator.resolver
    TargetValidator.resolver = staticmethod(lambda host: [ipaddress.ip_address("93.184.216.34")])
    try:
        result = gate.authorize_tool(
            auth_header=None,
            tool_name="nmap_scan",
            target="example.com",
            risk_level=RiskLevel.ACTIVE,
        )
        assert result.allowed, f"in-scope execution should be allowed: {result.policy.reason}"
        assert result.engagement is not None
        assert result.engagement.id == "ENG-001"

        # Out of scope is still refused.
        denied = gate.authorize_tool(
            auth_header=None,
            tool_name="nmap_scan",
            target="not-in-scope.com",
            risk_level=RiskLevel.ACTIVE,
        )
        assert not denied.allowed, "an out-of-scope target must still be denied"
    finally:
        TargetValidator.resolver = previous_resolver
    print("  [OK] In scope allowed, out of scope denied")


def test_ambiguous_engagement_denied(tmp: Path):
    """Two active engagements and no id named means denial, not a guess."""
    print("[TEST] Ambiguous engagement denied...")
    store = EngagementStore(base_dir=tmp)
    store.create(_payload(id="ENG-A"))
    store.create(_payload(id="ENG-B"))

    gate = SecurityGate(
        token_validator=TokenValidator(token=""),
        enforce=True,
        engagement_store=store,
    )
    result = gate.authorize_tool(
        auth_header=None,
        tool_name="nmap_scan",
        target="example.com",
        risk_level=RiskLevel.PASSIVE,
    )

    assert not result.allowed, "ambiguity must deny rather than pick one"
    assert "active engagements" in result.policy.reason
    print("  [OK] Ambiguity denied with both ids listed")


def test_unknown_engagement_id_denied(tmp: Path):
    """Naming an engagement that does not exist is denied."""
    print("[TEST] Unknown engagement id denied...")
    store = EngagementStore(base_dir=tmp)
    store.create(_payload())

    gate = SecurityGate(
        token_validator=TokenValidator(token=""),
        enforce=True,
        engagement_store=store,
    )
    result = gate.authorize_tool(
        auth_header=None,
        tool_name="nmap_scan",
        target="example.com",
        risk_level=RiskLevel.PASSIVE,
        engagement_id="ENG-DOES-NOT-EXIST",
    )

    assert not result.allowed
    assert "ENG-DOES-NOT-EXIST" in result.policy.reason
    print("  [OK] Unknown id denied")


def test_execution_record_carries_engagement(tmp: Path):
    """The execution record is stamped with the engagement it ran under."""
    print("[TEST] Execution record carries the engagement...")
    store = EngagementStore(base_dir=tmp)
    store.create(_payload())
    gate = SecurityGate(
        token_validator=TokenValidator(token=""),
        enforce=True,
        engagement_store=store,
    )
    service = ExecutionService(gate=gate)

    result = service.execute("nmap_scan", {"target": "out-of-scope.example.org"})
    record = service.registry.get(result["execution_id"])

    assert record.engagement_id == "ENG-001", (
        f"record should name the engagement it was checked against, got {record.engagement_id!r}"
    )
    print("  [OK] Record stamped with the engagement")


if __name__ == "__main__":
    import tempfile

    print("\n=== Engagement Tests ===\n")
    test_roundtrip_preserves_scope()
    test_invalid_ids_rejected()
    test_destructive_risk_cannot_be_granted()
    test_bad_dates_rejected()
    test_empty_allowlist_fails_validation()
    test_enforcement_defaults_on()

    for fn in (
        test_store_persists_across_instances,
        test_store_rejects_duplicate_without_overwrite,
        test_store_rejects_invalid_engagement,
        test_store_skips_corrupt_file,
        test_store_status_changes,
        test_store_concurrent_creates,
        test_default_engagement_only_when_unambiguous,
        test_fresh_install_denies_with_a_useful_message,
        test_in_scope_execution_allowed_after_creating_engagement,
        test_ambiguous_engagement_denied,
        test_unknown_engagement_id_denied,
        test_execution_record_carries_engagement,
    ):
        with tempfile.TemporaryDirectory() as raw:
            fn(Path(raw))

    print("\n=== All Engagement Tests Passed ===\n")
