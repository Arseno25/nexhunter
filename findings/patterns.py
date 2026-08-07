"""Curated bug-class reference: what experienced bug bounty triagers reject
on sight, and what looks alarming but is a known-safe pattern.

This is knowledge, not logic -- a static reference an AI client can read
before creating a finding or reasoning through gates.py, the same way
findings/attack.py is a curated CWE lookup rather than a live classifier.
Deliberately NOT a filter: matching a finding's title against these strings
and auto-rejecting it would be exactly the kind of unverified, code-made
judgment call the rest of findings/ refuses to make -- a title containing
"open redirect" is not proof it lacks a chain that makes it valid. Read it,
don't grep it.
"""

# Patterns that are near-universally rejected by web/API bug bounty programs
# on their own, absent a working chain to real impact. From bountyforge's
# "ALWAYS REJECTED" list, scoped to what applies without smart-contract
# tooling (see docs on the deferred smart-contract sub-project).
ALWAYS_REJECTED: tuple[str, ...] = (
    "missing CSP/HSTS/security headers alone",
    "missing SPF/DKIM/DMARC alone",
    "GraphQL introspection enabled, alone",
    "banner/version disclosure without a working exploit for that version",
    "clickjacking on a non-sensitive page",
    "tabnabbing",
    "CSV injection",
    "CORS wildcard without a credentialed exfiltration PoC",
    "logout CSRF (without session fixation)",
    "self-XSS (without an escalation path to a victim)",
    "open redirect, alone (no OAuth/token chain)",
    "OAuth client_secret embedded in a mobile app",
    "SSRF proven only via DNS ping (no internal access demonstrated)",
    "host header injection, alone",
    "missing rate limit on a non-critical form",
    "session not invalidated on logout",
    "concurrent sessions allowed",
    "internal IP address disclosure",
    "mixed content warnings",
    "weak TLS/SSL cipher suites, alone",
    "missing HttpOnly/Secure cookie flags, alone",
    "broken external links",
    "pre-account takeover (no proof the email is claimable)",
    "autocomplete enabled on a password field",
)

# Patterns that look like findings but are widely treated as by-design or
# already mitigated -- worth a second look before spending gate-review time.
SAFE_PATTERNS: tuple[str, ...] = (
    "rate limiting that genuinely prevents the exploitation path",
    "CSRF tokens that are validated correctly",
    "self-XSS with no escalation path to another user",
    "logout CSRF with no accompanying session fixation",
    "non-sensitive information disclosure (e.g. stack traces in a dev-only build)",
    "operator-supplied configuration treated as attacker input",
    "error messages exposing an HTTP status code or a generic library error, not credentials or PII",
)

__all__ = ["ALWAYS_REJECTED", "SAFE_PATTERNS"]
