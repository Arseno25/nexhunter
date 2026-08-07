"""Store-wide integrity audit (findings/ledger.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.findings import custody
from nexhunter.findings.ledger import audit
from nexhunter.findings.models import Category, Finding


def _finding(**overrides) -> Finding:
    payload = {"tool": "nuclei", "target": "x.example", "title": "t", "category": Category.VULNERABILITY.value}
    payload.update(overrides)
    return Finding(**payload)


def test_clean_store_has_no_issues():
    print("[TEST] a store with no confirmed-but-empty findings has no issues...")
    f = _finding(evidence={"request": "GET /x"})
    f.gate_status = "confirmed"
    assert audit([f]) == []
    print("  [OK]")


def test_confirmed_with_no_evidence_flagged():
    print("[TEST] confirmed/demoted with no evidence and no artifacts is flagged...")
    f = _finding()
    f.gate_status = "confirmed"
    issues = audit([f])
    assert len(issues) == 1
    assert issues[0].kind == "no_evidence"
    assert issues[0].finding_id == f.id
    print("  [OK]")


def test_demoted_with_no_evidence_also_flagged():
    print("[TEST] demoted (not just confirmed) with no evidence is also flagged...")
    f = _finding()
    f.gate_status = "demoted"
    issues = audit([f])
    assert any(i.kind == "no_evidence" for i in issues)
    print("  [OK]")


def test_unreviewed_or_refuted_with_no_evidence_not_flagged():
    """Only confirmed/demoted make a claim worth backing with evidence --
    an unreviewed or refuted finding hasn't claimed to survive the gates."""
    print("[TEST] unreviewed/refuted findings are not flagged for missing evidence...")
    unreviewed = _finding()
    refuted = _finding()
    refuted.gate_status = "refuted"
    assert audit([unreviewed, refuted]) == []
    print("  [OK]")


def test_artifacts_alone_satisfy_the_evidence_check():
    print("[TEST] artifacts alone (no evidence dict) satisfy the check...")
    f = _finding(artifacts=["screenshot.png"])
    f.gate_status = "confirmed"
    assert audit([f]) == []
    print("  [OK]")


def test_broken_custody_chain_flagged():
    print("[TEST] a tampered custody chain is flagged as custody_broken...")
    f = _finding(evidence={"request": "GET /x"})
    f.gate_status = "confirmed"
    chain = custody.append([], "created", {"tool": "nuclei"})
    chain[0] = {**chain[0], "data": {"tool": "TAMPERED"}}
    f.custody_chain = chain
    issues = audit([f])
    assert any(i.kind == "custody_broken" for i in issues)
    print("  [OK]")


def test_to_dict_shape():
    print("[TEST] LedgerIssue.to_dict has the expected keys...")
    f = _finding()
    f.gate_status = "confirmed"
    issue = audit([f])[0]
    assert set(issue.to_dict()) == {"finding_id", "kind", "detail"}
    print("  [OK]")
