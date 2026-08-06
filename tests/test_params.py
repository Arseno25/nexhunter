"""Typed parameter validation."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.core import params as P
from nexhunter.core import tools as T
from nexhunter.core.params import ParamSpec, ParamType, ValidationError


def _spec(param_type: ParamType, **kwargs) -> ParamSpec:
    return ParamSpec(name="value", type=param_type, **kwargs)


def _rejects(spec: ParamSpec, value, hint: str = "") -> str:
    """Assert a value is rejected, returning the message."""
    try:
        spec.validate(value)
    except ValidationError as exc:
        return str(exc)
    raise AssertionError(f"expected {value!r} to be rejected {hint}")


# --------------------------------------------------------------------------
# Injection and control characters
# --------------------------------------------------------------------------

def test_option_injection_rejected():
    """A value that would be read as a command-line option is refused.

    Builders place values positionally, so "--script=x" as a target would
    inject an option into a tool the caller was only meant to point at a host.
    """
    print("[TEST] Option injection rejected...")
    spec = _spec(ParamType.TARGET)

    for payload in ["--script=http-shellshock", "-oN/tmp/out", "--data-dir=/etc", "-"]:
        message = _rejects(spec, payload)
        assert "option" in message, f"unexpected reason for {payload!r}: {message}"

    print("  [OK] Leading-dash values refused")


def test_null_byte_and_control_characters_rejected():
    """Null bytes and control characters never reach a builder."""
    print("[TEST] Null bytes and control characters rejected...")
    spec = _spec(ParamType.STRING)

    assert "null byte" in _rejects(spec, "example\x00.com")
    assert "control character" in _rejects(spec, "example\n.com")
    assert "control character" in _rejects(spec, "example\r.com")

    print("  [OK] Null bytes and control characters refused")


def test_excessive_length_rejected():
    """Absurdly long values are refused rather than passed to a tool."""
    print("[TEST] Excessive length rejected...")
    spec = _spec(ParamType.STRING, max_length=64)

    assert "exceeds" in _rejects(spec, "a" * 65)
    assert spec.validate("a" * 64) == "a" * 64

    print("  [OK] Length capped")


def test_shell_metacharacters_are_data_not_syntax():
    """Metacharacters are rejected as hostnames, never treated as syntax."""
    print("[TEST] Shell metacharacters handled as data...")
    spec = _spec(ParamType.HOSTNAME)

    for payload in ["example.com; whoami", "example.com && id", "$(whoami).com", "`id`.com"]:
        _rejects(spec, payload, "as a hostname")

    # In a free-text field they survive intact as one literal value: argv is
    # passed without a shell, so they are data.
    text = _spec(ParamType.STRING).validate("a; whoami && id")
    assert text == "a; whoami && id"

    print("  [OK] Rejected where typed, inert where free-text")


# --------------------------------------------------------------------------
# Per-type validation
# --------------------------------------------------------------------------

def test_hostname_validation():
    """Hostnames are validated and normalized."""
    print("[TEST] Hostname validation...")
    spec = _spec(ParamType.HOSTNAME)

    assert spec.validate("Example.COM") == "example.com"
    assert spec.validate("sub.example.com.") == "sub.example.com"

    for bad in ["", "not a host", "-leading.com", "trailing-.com", "a" * 300 + ".com"]:
        _rejects(spec, bad or None if bad == "" else bad) if bad else None

    _rejects(spec, "not a host")
    _rejects(spec, "exam ple.com")

    print("  [OK] Hostnames validated and lowercased")


def test_ip_and_cidr_validation():
    """IP addresses and CIDR blocks are validated."""
    print("[TEST] IP and CIDR validation...")
    ip = _spec(ParamType.IP_ADDRESS)
    assert ip.validate("192.168.1.1") == "192.168.1.1"
    assert ip.validate("2001:db8::1") == "2001:db8::1"
    _rejects(ip, "999.1.1.1")
    _rejects(ip, "example.com")

    cidr = _spec(ParamType.CIDR)
    assert cidr.validate("10.0.0.0/8") == "10.0.0.0/8"
    _rejects(cidr, "10.0.0.0/33")

    print("  [OK] IPs and CIDRs validated")


def test_url_validation():
    """URLs are validated, and unsafe schemes are refused."""
    print("[TEST] URL validation...")
    spec = _spec(ParamType.URL)

    assert spec.validate("https://Example.com/path") == "https://example.com/path"
    assert spec.validate("example.com").startswith("https://")

    for scheme in ["file:///etc/passwd", "gopher://x/", "javascript:alert(1)", "ftp://x/"]:
        message = _rejects(spec, scheme)
        assert "scheme" in message or "host" in message, f"unexpected: {message}"

    print("  [OK] Only http and https accepted")


def test_url_credentials_rejected():
    """A URL carrying credentials is refused, not silently stripped.

    Credentials in a URL land in logs and process listings. Rejecting tells the
    caller they were dropped; stripping would hide it.
    """
    print("[TEST] URL credentials rejected...")
    spec = _spec(ParamType.URL)
    assert "credentials" in _rejects(spec, "https://admin:hunter2@example.com/")
    print("  [OK] Embedded credentials refused")


def test_port_and_range_validation():
    """Ports and port ranges are validated."""
    print("[TEST] Port validation...")
    port = _spec(ParamType.PORT)
    assert port.validate("443") == "443"
    assert port.validate(80) == "80"
    _rejects(port, "0")
    _rejects(port, "65536")
    _rejects(port, "http")

    ports = _spec(ParamType.PORT_RANGE)
    assert ports.validate("80,443,8000-9000") == "80,443,8000-9000"
    _rejects(ports, "443-80", "(range reversed)")
    _rejects(ports, "80,,443", "(empty entry)")
    _rejects(ports, "80,99999")
    _rejects(ports, "80;whoami")

    print("  [OK] Ports and ranges validated")


def test_enum_and_integer_bounds():
    """Enums and integer bounds are enforced."""
    print("[TEST] Enum and integer bounds...")
    enum = _spec(ParamType.ENUM, choices=("tcp", "udp"))
    assert enum.validate("tcp") == "tcp"
    assert "one of" in _rejects(enum, "sctp")

    number = _spec(ParamType.INTEGER, minimum=1, maximum=100)
    assert number.validate("50") == 50
    assert "at least" in _rejects(number, "0")
    assert "at most" in _rejects(number, "101")
    _rejects(number, "abc")

    print("  [OK] Enums and bounds enforced")


def test_boolean_and_duration():
    """Booleans and durations are parsed."""
    print("[TEST] Boolean and duration...")
    flag = _spec(ParamType.BOOLEAN)
    assert flag.validate("true") is True
    assert flag.validate("off") is False
    _rejects(flag, "maybe")

    duration = _spec(ParamType.DURATION, maximum=3600)
    assert duration.validate("30s") == "30s"
    assert duration.validate("5m") == "5m"
    _rejects(duration, "2d", "(exceeds the maximum)")
    _rejects(duration, "soon")

    print("  [OK] Booleans and durations parsed")


# --------------------------------------------------------------------------
# Filesystem parameters
# --------------------------------------------------------------------------

def test_file_must_exist(tmp: Path):
    """A file parameter must point at a real file."""
    print("[TEST] File parameters must exist...")
    spec = _spec(ParamType.FILE)

    existing = tmp / "wordlist.txt"
    existing.write_text("admin\n", encoding="utf-8")
    assert spec.validate(str(existing)) == str(existing.resolve())

    assert "does not exist" in _rejects(spec, str(tmp / "missing.txt"))
    assert "not a file" in _rejects(spec, str(tmp))

    print("  [OK] Missing and non-file paths refused")


def test_path_traversal_confined_when_roots_configured(tmp: Path):
    """With allowed roots set, a path outside them is refused."""
    print("[TEST] File paths confined to allowed roots...")
    allowed = tmp / "allowed"
    allowed.mkdir()
    inside = allowed / "list.txt"
    inside.write_text("x", encoding="utf-8")

    outside = tmp / "outside.txt"
    outside.write_text("secret", encoding="utf-8")

    spec = _spec(ParamType.WORDLIST)
    previous = os.environ.get("NEXHUNTER_ALLOWED_PATHS")
    os.environ["NEXHUNTER_ALLOWED_PATHS"] = str(allowed)
    try:
        assert spec.validate(str(inside)) == str(inside.resolve())

        assert "outside the permitted roots" in _rejects(spec, str(outside))
        # Traversal out of the allowed root is refused too.
        traversal = allowed / ".." / "outside.txt"
        assert "outside the permitted roots" in _rejects(spec, str(traversal))
    finally:
        if previous is None:
            os.environ.pop("NEXHUNTER_ALLOWED_PATHS", None)
        else:
            os.environ["NEXHUNTER_ALLOWED_PATHS"] = previous

    print("  [OK] Paths confined, traversal refused")


# --------------------------------------------------------------------------
# Parameter sets
# --------------------------------------------------------------------------

def test_unknown_parameters_rejected():
    """An unknown parameter is an error, not silently dropped.

    Dropping one hides a typo that would otherwise change what a tool does.
    """
    print("[TEST] Unknown parameters rejected...")
    specs = (ParamSpec(name="target", type=ParamType.TARGET, required=True),)

    _, error = P.validate_params(specs, {"target": "example.com", "typo": "x"})
    assert error and "unknown parameter" in error

    values, error = P.validate_params(specs, {"target": "example.com"})
    assert error is None and values["target"] == "example.com"

    print("  [OK] Unknown parameters refused")


def test_required_parameter_enforced():
    """A missing required parameter is refused."""
    print("[TEST] Required parameters enforced...")
    specs = (ParamSpec(name="target", type=ParamType.TARGET, required=True),)

    _, error = P.validate_params(specs, {})
    assert error and "required" in error

    print("  [OK] Required parameters enforced")


def test_defaults_applied():
    """Optional parameters fall back to their declared default."""
    print("[TEST] Defaults applied...")
    specs = (
        ParamSpec(name="target", type=ParamType.TARGET, required=True),
        ParamSpec(name="ports", type=ParamType.PORT_RANGE, default="80,443"),
    )
    values, error = P.validate_params(specs, {"target": "example.com"})

    assert error is None
    assert values["ports"] == "80,443"

    print("  [OK] Defaults applied")


# --------------------------------------------------------------------------
# Registry integration
# --------------------------------------------------------------------------

def test_every_tool_has_typed_parameters():
    """All registry tools carry typed schemas, inferred where not declared."""
    print("[TEST] Registry-wide typed parameters...")
    for name, spec in T.TOOLS.items():
        assert spec.param_specs is not None, f"{name} has no param_specs"
        assert len(spec.param_specs) == len(spec.params), f"{name} schema/params mismatch"
        for param in spec.param_specs:
            assert isinstance(param.type, ParamType), f"{name}.{param.name} has no type"

    print(f"  [OK] {len(T.TOOLS)} tools carry typed schemas")


def test_registry_rejects_injection_through_a_real_tool():
    """A real tool refuses an option-injection payload end to end."""
    print("[TEST] Registry tool rejects injection...")
    spec = T.get_tool_spec("nmap_scan")

    ok, error = spec.validate({"target": "--script=http-shellshock"})
    assert not ok and "option" in error
    assert spec.build_cmd({"target": "--script=http-shellshock"}) is None

    ok, error = spec.validate({"target": "example.com", "ports": "80;whoami"})
    assert not ok, "a port list with a metacharacter must be refused"

    argv = spec.build_cmd({"target": "Example.com", "ports": "80,443"})
    assert argv and "example.com" in argv, f"normalized value should reach argv: {argv}"

    print("  [OK] Injection refused, valid input normalized")


def test_secret_parameters_detected():
    """Credential-carrying parameters are marked secret by the schema."""
    print("[TEST] Secret parameters detected...")
    spec = T.get_tool_spec("wpscan_scan")
    assert "api_token" in spec.secret_params()

    assert P.is_secret_name("api_token")
    assert P.is_secret_name("PASSWORD")
    assert not P.is_secret_name("target")
    assert not P.is_secret_name("ports")

    print("  [OK] Secret parameters marked")


def test_schema_driven_redaction_beats_flag_guessing():
    """A declared secret is masked even on a flag no heuristic would know."""
    print("[TEST] Schema-driven redaction...")
    from nexhunter.security.redaction import SecretRedactor

    redactor = SecretRedactor()
    argv = ["obscure-tool", "--totally-unlisted-flag", "sup3rs3cret", "--url", "https://x"]

    guessed = redactor.redact_command(argv)
    assert "sup3rs3cret" in guessed, "the heuristic cannot know this flag; that is the point"

    declared = redactor.redact_command(argv, secret_values=["sup3rs3cret"])
    assert "sup3rs3cret" not in declared
    assert "[REDACTED]" in declared

    print("  [OK] Declared secrets masked where guessing fails")


def test_optimizer_query_param_only_filled_for_whois():
    """A "query" parameter is target-shaped only for whois_lookup.

    cve_search, searchsploit, shodan, censys and zoomeye use "query" for a
    search string; auto-filling it with the target hostname pollutes the
    search.
    """
    print("[TEST] Optimizer query parameter scoping...")
    from nexhunter.agents.param_optimizer import ParameterOptimizer

    opt = ParameterOptimizer()

    whois = T.get_tool_spec("whois_lookup")
    params = opt.optimize(whois, "example.com")
    assert params.get("query") == "example.com"

    for name in ("cve_search", "searchsploit", "shodan", "censys", "zoomeye"):
        spec = T.get_tool_spec(name)
        params = opt.optimize(spec, "example.com")
        assert "query" not in params, f"{name} query must not be auto-filled with the hostname"

    print("  [OK] Search-tool queries left alone")


if __name__ == "__main__":
    print("\n=== Typed Parameter Tests ===\n")
    test_option_injection_rejected()
    test_null_byte_and_control_characters_rejected()
    test_excessive_length_rejected()
    test_shell_metacharacters_are_data_not_syntax()
    test_hostname_validation()
    test_ip_and_cidr_validation()
    test_url_validation()
    test_url_credentials_rejected()
    test_port_and_range_validation()
    test_enum_and_integer_bounds()
    test_boolean_and_duration()
    with tempfile.TemporaryDirectory() as raw:
        test_file_must_exist(Path(raw))
    with tempfile.TemporaryDirectory() as raw:
        test_path_traversal_confined_when_roots_configured(Path(raw))
    test_unknown_parameters_rejected()
    test_required_parameter_enforced()
    test_defaults_applied()
    test_every_tool_has_typed_parameters()
    test_registry_rejects_injection_through_a_real_tool()
    test_secret_parameters_detected()
    test_schema_driven_redaction_beats_flag_guessing()
    test_optimizer_query_param_only_filled_for_whois()
    print("\n=== All Typed Parameter Tests Passed ===\n")
