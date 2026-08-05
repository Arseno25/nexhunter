"""Parsers for the newly-matured recon/crawl tools.

A tool is not "stable" until its output can be turned into structured data and
that transform is tested. These cover the line- and JSON-based parsers wired to
katana/gau/waybackurls (urls), subfinder/assetfinder/amass (hosts), naabu
(host_port), and dnsx (dnsx_resp).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.core import tools as T


def test_urls_parser_dedupes_and_keeps_order():
    print("[TEST] urls parser...")
    text = "https://a.example.com/1\nhttps://a.example.com/2\nhttps://a.example.com/1\n\n"
    out = T.parse_output("gau", text)
    assert out == [
        {"url": "https://a.example.com/1"},
        {"url": "https://a.example.com/2"},
    ]
    print("  [OK] URLs parsed, deduped, ordered")


def test_hosts_parser_lowercases_and_dedupes():
    print("[TEST] hosts parser...")
    text = "API.Example.com\napi.example.com\nblog.example.com\n"
    out = T.parse_output("subfinder_enum", text)
    assert out == [{"host": "api.example.com"}, {"host": "blog.example.com"}]
    print("  [OK] Hosts normalized")


def test_host_port_parser():
    print("[TEST] host_port parser (naabu)...")
    text = "192.168.1.10:22\n192.168.1.10:443\ngarbage-line\n"
    out = T.parse_output("naabu", text)
    assert out == [
        {"host": "192.168.1.10", "port": "22"},
        {"host": "192.168.1.10", "port": "443"},
    ]
    print("  [OK] host:port parsed, junk ignored")


def test_dnsx_resp_parser():
    print("[TEST] dnsx_resp parser...")
    text = "www.example.com [93.184.216.34]\nmail.example.com [93.184.216.35] [93.184.216.36]\n"
    out = T.parse_output("dnsx", text)
    assert out[0] == {"host": "www.example.com", "a": ["93.184.216.34"]}
    assert out[1]["host"] == "mail.example.com"
    assert out[1]["a"] == ["93.184.216.35", "93.184.216.36"]
    print("  [OK] dnsx host + A records parsed")


def test_matured_tools_are_stable_and_parsed():
    """The promoted tools report stable maturity and resolve a parser."""
    print("[TEST] matured tools are stable...")
    for name in ("katana_crawl", "gau", "waybackurls", "naabu", "dnsx"):
        spec = T.get_tool_spec(name)
        assert spec is not None, name
        assert spec.maturity == "stable", f"{name} should be stable, is {spec.maturity}"
        assert spec.parser in T.PARSERS, f"{name} parser {spec.parser} not registered"
    print("  [OK] 5 tools stable with working parsers")


if __name__ == "__main__":
    print("\n=== Tool Parser Tests ===\n")
    test_urls_parser_dedupes_and_keeps_order()
    test_hosts_parser_lowercases_and_dedupes()
    test_host_port_parser()
    test_dnsx_resp_parser()
    test_matured_tools_are_stable_and_parsed()
    print("\n=== All Tool Parser Tests Passed ===\n")
