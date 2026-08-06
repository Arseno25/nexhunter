"""CVE watch agent: severity scoring + exploit-kind classification."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.agents.cve_watch import CVEWatchAgent
from nexhunter.agents import AGENTS


def test_agent_is_discovered():
    assert "cve_watch" in AGENTS


def _fake_cve(cid, desc, severity="HIGH", cvss=8.1, refs=()):
    return {
        "id": cid,
        "descriptions": [{"lang": "en", "value": desc}],
        "metrics": {
            "cvssMetricV31": [{
                "cvssData": {"baseScore": cvss, "baseSeverity": severity},
            }],
        },
        "references": [{"url": r} for r in refs],
    }


def test_classify_kinds():
    classify = CVEWatchAgent._classify
    assert classify("remote code execution in parser") == "rce"
    assert classify("sql injection in search") == "sqli"
    assert classify("cross-site scripting") == "xss"
    assert classify("path traversal leads to local file read") == "lfi"
    assert classify("server-side request forgery") == "ssrf"
    assert classify("authentication bypass") == "auth"
    assert classify("memory leak in widget") == "generic"


def test_score_extracts_metrics_and_hints():
    agent = CVEWatchAgent(None)
    item = agent._score(_fake_cve(
        "CVE-2024-0001",
        "remote code execution via crafted packet",
        severity="CRITICAL", cvss=9.8,
        refs=("https://www.exploit-db.com/exploits/123", "https://example.org"),
    ))
    assert item["cve"] == "CVE-2024-0001"
    assert item["severity"] == "CRITICAL"
    assert item["cvss"] == 9.8
    assert item["kind"] == "rce"
    assert "exploit-db" in item["poc_hints"]
    assert item["exploitability"] >= 8


def test_score_low_profile_is_less_exploitable():
    agent = CVEWatchAgent(None)
    item = agent._score(_fake_cve(
        "CVE-2024-0002",
        "minor memory leak in widget library",
        severity="LOW", cvss=3.1,
    ))
    assert item["kind"] == "generic"
    assert item["exploitability"] < 6
    assert item["poc_hints"] == []


def test_ranking_puts_critical_actionable_first():
    agent = CVEWatchAgent(None)
    exploitables = [
        agent._score(_fake_cve("A", "rce with public exploit",
                                      "CRITICAL", 9.8,
                                      refs=("https://x/exploit",))),
        agent._score(_fake_cve("B", "minor info disclosure",
                                      "LOW", 2.0)),
    ]
    exploitables.sort(key=lambda x: (x["exploitability"], x["cvss"]),
                      reverse=True)
    assert exploitables[0]["cve"] == "A"
