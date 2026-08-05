"""Parameter optimization: invoke each tool the way its function expects.

The recurring failure this prevents is feeding a hostname-typed parameter a raw
URL (or a content brute-forcer no wordlist) so the tool is rejected before it
ever runs. These tests pin the target-form derivation, the wordlist fill, and
the refusal to fabricate parameters that only an operator can supply.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.agents import param_optimizer as PO
from nexhunter.agents.param_optimizer import ParameterOptimizer, optimize_preview
from nexhunter.agents.profiler import Profiler
from nexhunter.core import tools as T


def _params(tool, target="https://example.com", objective="standard"):
    spec = T.get_tool_spec(tool)
    profile = Profiler().new_profile(target)
    return spec, ParameterOptimizer().optimize(spec, target, profile, objective)


# --------------------------------------------------------------------------
# Target-form derivation
# --------------------------------------------------------------------------

def test_domain_param_gets_bare_hostname_from_url():
    """A hostname-typed parameter must never receive a raw URL."""
    print("[TEST] domain param -> bare hostname...")
    for tool in ("dns_lookup", "subfinder_enum"):
        _, params = _params(tool)
        assert params.get("domain") == "example.com", (tool, params)
    print("  [OK] scheme and path stripped")


def test_url_param_gets_full_url():
    """A URL-typed parameter keeps a scheme."""
    print("[TEST] url param -> full URL...")
    for tool in ("wpscan_scan", "curl_headers"):
        _, params = _params(tool)
        assert params.get("url", "").startswith("http"), (tool, params)
    print("  [OK] scheme present")


def test_scanner_target_is_a_host_not_a_url():
    """nmap and friends want a host/IP, not a URL."""
    print("[TEST] scanner target -> host...")
    _, params = _params("nmap_scan")
    assert params.get("target") == "example.com", params
    assert "://" not in params.get("target", ""), params
    print("  [OK] host form for the scanner")


def test_web_target_gets_web_ports():
    """A web target narrows nmap to the web ports."""
    print("[TEST] web target -> web ports...")
    _, params = _params("nmap_scan", "https://example.com")
    assert params.get("ports") == PO._WEB_PORTS, params
    _, host_params = _params("nmap_scan", "192.168.1.10")
    assert "ports" not in host_params, "a bare host keeps the default sweep"
    print("  [OK] ports tuned for web, default for host")


# --------------------------------------------------------------------------
# Required parameters: fill what we can, never fabricate the rest
# --------------------------------------------------------------------------

def test_required_wordlist_is_filled_from_installed_list(monkeypatch=None):
    """A content brute-forcer gets an installed wordlist so it can run."""
    print("[TEST] required wordlist filled...")
    with tempfile.NamedTemporaryFile(suffix=".txt") as tmp:
        original = PO._DIR_WORDLISTS
        PO._DIR_WORDLISTS = (tmp.name,)
        try:
            spec, params = _params("gobuster_dir")
            assert params.get("wordlist") == tmp.name, params
            # And the completed set actually validates + builds.
            normalized, err = spec.normalize(params)
            assert err is None, err
            assert spec.build_cmd(normalized), "command should build"
        finally:
            PO._DIR_WORDLISTS = original
    print("  [OK] wordlist filled and command builds")


def test_dns_and_dir_tools_get_different_wordlists():
    """A DNS brute-forcer must not be handed a web-content list."""
    print("[TEST] dns vs dir wordlist...")
    opt = ParameterOptimizer()
    dns = opt._wordlist_for(T.get_tool_spec("gobuster_dns"))
    web = opt._wordlist_for(T.get_tool_spec("gobuster_dir"))
    # Both may be None on a bare host; only assert the routing when present.
    if dns and web:
        assert "dns" in dns.lower() or "subdomain" in dns.lower(), dns
        assert dns != web, "dns and dir lists should differ"
    print(f"  [OK] dns={bool(dns)} dir={bool(web)}")


def test_file_target_routes_into_a_file_parameter():
    """A binary target flows into a tool's file parameter and validates."""
    print("[TEST] file target -> file param...")
    with tempfile.NamedTemporaryFile(suffix=".bin") as tmp:
        tmp.write(b"\x7fELF binary contents")
        tmp.flush()
        spec = T.get_tool_spec("strings")
        profile = Profiler().new_profile(tmp.name)
        assert profile.target_type == "binary", profile.target_type
        params = ParameterOptimizer().optimize(spec, tmp.name, profile)
        assert params.get("file") == tmp.name, params
        _, err = spec.normalize(params)
        assert err is None, err
    print("  [OK] file routed and validates")


def test_file_param_not_filled_for_a_web_target():
    """A web target must never be poured into a file parameter."""
    print("[TEST] web target leaves file params empty...")
    spec = T.get_tool_spec("strings")
    profile = Profiler().new_profile("https://example.com")
    params = ParameterOptimizer().optimize(spec, "https://example.com", profile)
    assert "file" not in params, params
    print("  [OK] file param left unset for web")


def test_objective_tunes_scanner_rate():
    """Stealth scans slow, comprehensive scans hammer."""
    print("[TEST] objective -> scan rate...")
    _, stealth = _params("masscan", "10.0.0.1", objective="stealth")
    _, comp = _params("masscan", "10.0.0.1", objective="comprehensive")
    assert stealth["rate"] < comp["rate"], (stealth, comp)
    print(f"  [OK] stealth rate={stealth['rate']} < comprehensive rate={comp['rate']}")


def test_objective_tunes_crawl_depth():
    """Crawl shallow under stealth, deep under comprehensive."""
    print("[TEST] objective -> crawl depth...")
    _, stealth = _params("katana_crawl", objective="stealth")
    _, comp = _params("katana_crawl", objective="comprehensive")
    assert stealth["depth"] == 1 and comp["depth"] == 5, (stealth, comp)
    print(f"  [OK] depth {stealth['depth']} -> {comp['depth']}")


def test_optimizer_does_not_fabricate_a_hash_file():
    """A tool needing an operator-supplied file is left unfilled, not guessed."""
    print("[TEST] no fabricated hashfile...")
    _, params = _params("john", "deadbeef")
    assert "hashfile" not in params, params
    print("  [OK] refused to invent a file")


# --------------------------------------------------------------------------
# Preview API
# --------------------------------------------------------------------------

def test_objective_tunes_nmap_timing():
    """Stealth scans slowly, comprehensive scans fast."""
    print("[TEST] objective -> nmap timing...")
    _, stealth = _params("nmap_scan", objective="stealth")
    _, comprehensive = _params("nmap_scan", objective="comprehensive")
    assert stealth["timing"] == "2", stealth
    assert comprehensive["timing"] == "5", comprehensive
    print(f"  [OK] stealth=T{stealth['timing']} comprehensive=T{comprehensive['timing']}")


def test_objective_tunes_nuclei_severity():
    """Quick runs only the loud findings; comprehensive runs everything."""
    print("[TEST] objective -> nuclei severity...")
    _, quick = _params("nuclei_scan", objective="quick")
    _, comprehensive = _params("nuclei_scan", objective="comprehensive")
    assert quick.get("severity") == "critical,high", quick
    assert "severity" not in comprehensive, "comprehensive omits the floor (all severities)"
    print("  [OK] severity floor scales with objective")


def test_extensions_follow_detected_technology():
    """A brute-forcer's extensions match the detected stack."""
    print("[TEST] tech -> extensions...")
    profiler = Profiler()
    php = profiler.new_profile("https://example.com")
    profiler.observe(php, "httpx_probe", [{"tech": ["PHP"]}], "e1")
    spec = T.get_tool_spec("gobuster_dir")
    params = ParameterOptimizer().optimize(spec, "https://example.com", php, "standard")
    assert params.get("extensions") == "php,html,txt", params
    print(f"  [OK] PHP -> {params['extensions']}")


def test_optimize_preview_is_runnable_for_web_tools():
    """The preview builds a runnable command for a normal web tool."""
    print("[TEST] optimize_preview runnable...")
    result = optimize_preview("https://example.com", "httpx_probe")
    assert result["ok"] and result["runnable"], result
    assert result["command"] and result["command"][0] == "httpx", result
    print(f"  [OK] {' '.join(result['command'])}")


def test_optimize_preview_rejects_unknown_tool():
    print("[TEST] optimize_preview unknown tool...")
    result = optimize_preview("https://example.com", "not_a_real_tool")
    assert not result["ok"] and result["code"] == "UNKNOWN_TOOL", result
    print("  [OK] unknown tool reported")


def test_common_web_tools_all_validate():
    """Every common web tool ends up with a parameter set that validates."""
    print("[TEST] common web tools validate...")
    for tool in ("httpx_probe", "nuclei_scan", "wpscan_scan", "nikto_scan",
                 "dalfox_xss", "curl_headers"):
        spec, params = _params(tool)
        _, err = spec.normalize(params)
        assert err is None, f"{tool}: {err}"
    print("  [OK] all validate")


if __name__ == "__main__":
    test_domain_param_gets_bare_hostname_from_url()
    test_url_param_gets_full_url()
    test_scanner_target_is_a_host_not_a_url()
    test_web_target_gets_web_ports()
    test_required_wordlist_is_filled_from_installed_list()
    test_dns_and_dir_tools_get_different_wordlists()
    test_file_target_routes_into_a_file_parameter()
    test_file_param_not_filled_for_a_web_target()
    test_objective_tunes_scanner_rate()
    test_objective_tunes_crawl_depth()
    test_optimizer_does_not_fabricate_a_hash_file()
    test_objective_tunes_nmap_timing()
    test_objective_tunes_nuclei_severity()
    test_extensions_follow_detected_technology()
    test_optimize_preview_is_runnable_for_web_tools()
    test_optimize_preview_rejects_unknown_tool()
    test_common_web_tools_all_validate()
    print("\nAll optimizer tests passed.")
