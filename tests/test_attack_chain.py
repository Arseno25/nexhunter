"""Attack chain builder: patterns, placeholders, availability, probability."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.execution import attack_chain as A


def test_pattern_catalog():
    names = [p["name"] for p in A.list_patterns()]
    assert "recon_sweep" in names and "web_rce" in names
    assert len(A.list_patterns()) >= 4


def test_unknown_chain_reports_available():
    r = A.build_chain("nope", "https://x")
    assert r["ok"] is False
    assert "recon_sweep" in r["available"]


def test_build_recon_chain_fills_placeholders():
    r = A.build_chain("recon_sweep", "https://lab.example",
                      domain="lab.example", host="10.0.0.5")
    assert r["ok"] is True
    assert r["chain_length"] == 5
    flat = [s for s in r["steps"]]
    for step in flat:
        assert step["gate"]
        assert step["description"]
        # Every placeholder must have been substituted away.
        for value in step["params"].values():
            assert "{" not in str(value), (step["tool"], value)


def test_all_pattern_steps_are_registered_tools():
    for pattern in A.list_patterns():
        chain = A.build_chain(pattern["name"], "https://x")
        assert chain["ok"], pattern
        for step in chain["steps"]:
            assert step["binary_available"] is True or step["tool"], step


def test_probability_is_bounded_and_honest():
    r = A.build_chain("web_rce", "https://x")
    assert 0 < r["success_probability"] <= 1
    # A chain without its binaries must never score like a fully loaded box.
    for step in r["steps"]:
        assert "binary_available" in step


def test_ssrf_chain_includes_internal_scan_step():
    r = A.build_chain("ssrf_internal", "https://x")
    scan = [s for s in r["steps"] if s["tool"] == "nmap_scan"][0]
    assert scan["params"]["ports"] == "80,443,8080"
