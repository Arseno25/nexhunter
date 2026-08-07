"""Chain of custody: hash-linked, tamper-evident audit trail."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.findings.custody import GENESIS_HASH, append, verify


def test_empty_chain_verifies_intact():
    print("[TEST] empty chain verifies intact...")
    assert verify([]) == (True, None)
    print("  [OK]")


def test_first_link_chains_from_genesis():
    print("[TEST] first link's prev_hash is the genesis hash...")
    chain = append([], "created", {"tool": "nuclei"})
    assert chain[0]["prev_hash"] == GENESIS_HASH
    assert chain[0]["seq"] == 0
    print("  [OK]")


def test_append_never_mutates_input():
    print("[TEST] append() returns a new list, never mutates the one it's given...")
    original = append([], "created", {})
    before = list(original)
    new_chain = append(original, "gated", {"gate_status": "confirmed"})
    assert original == before, "append() must not mutate its input"
    assert len(new_chain) == len(original) + 1
    print("  [OK]")


def test_multi_link_chain_verifies_intact():
    print("[TEST] a multi-link chain verifies intact...")
    chain = append([], "created", {"tool": "nuclei"})
    chain = append(chain, "gated", {"gate_status": "confirmed"})
    chain = append(chain, "reported", {"platform": "hackerone"})
    assert verify(chain) == (True, None)
    print("  [OK]")


def test_tampered_data_breaks_verification():
    print("[TEST] altering a past link's data breaks verification...")
    chain = append([], "created", {"tool": "nuclei"})
    chain = append(chain, "gated", {"gate_status": "confirmed"})
    tampered = [dict(chain[0]), dict(chain[1])]
    tampered[0] = {**tampered[0], "data": {"tool": "HACKED"}}
    intact, reason = verify(tampered)
    assert intact is False
    assert "link 0" in reason
    print("  [OK]")


def test_deleted_link_breaks_prev_hash_chain():
    print("[TEST] deleting a middle link breaks the prev_hash chain for what follows...")
    chain = append([], "created", {})
    chain = append(chain, "gated", {})
    chain = append(chain, "reported", {})
    # Delete the middle link and fix up seq numbers, as a naive tamperer might.
    spliced = [dict(chain[0]), {**dict(chain[2]), "seq": 1}]
    intact, reason = verify(spliced)
    assert intact is False
    print(f"  [OK] {reason}")


def test_reordered_links_detected():
    print("[TEST] swapping link order is detected...")
    chain = append([], "created", {})
    chain = append(chain, "gated", {})
    swapped = [chain[1], chain[0]]
    intact, _ = verify(swapped)
    assert intact is False
    print("  [OK]")
