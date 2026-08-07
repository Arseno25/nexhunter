"""Curated bug-bounty hunting reference: attack vectors to look for, bug
classes triagers reject on sight, false-positive patterns, and impact/
severity calibration.

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

# Vulnerability classes worth checking for, grouped the way a hunter walks
# an attack surface. Not exhaustive, not a scanner ruleset -- a reading list
# to jog what to look for in a category, same restraint as everything above:
# a category name is a prompt to go look, never a claim that it's present.
ATTACK_VECTORS: dict[str, tuple[str, ...]] = {
    "authentication": (
        "JWT alg:none, weak secret, or expired-token acceptance",
        "OAuth state CSRF, redirect_uri manipulation, token leakage via referrer",
        "password reset: host header injection in the reset link, predictable token, no expiry, concurrent reuse",
        "session fixation, session riding, session not invalidated on logout",
        "email-confirmation bypass: confirmation sent to the old email instead of the new one -> account takeover via SSO",
        "session cookie theft via HTTP request smuggling (CL.TE desync -> redirect -> cookie exfil)",
    ),
    "authorization": (
        "IDOR: horizontal (peer resources) and vertical (admin resources)",
        "mass assignment via undocumented fields (role, is_admin, balance)",
        "function-level auth checked by middleware but not by the handler itself",
        "GraphQL: missing auth on a mutation, IDOR via node IDs, batch-query abuse",
        "tenant isolation failure in a multi-tenant SaaS",
    ),
    "injection": (
        "SQLi: error-based, time-based, UNION, blind",
        "CSV injection via a leading =, +, -, or @ in an exported spreadsheet field",
        "SSTI: Jinja2, Twig, FreeMarker, Velocity",
        "command injection via ;, |, or $()",
        "XXE via a SYSTEM entity or an out-of-band external DTD",
        "SSRF against cloud metadata, the internal network, or localhost",
        "path traversal (../, ....//) in an upload/download file-path parameter",
        "open redirect via an unvalidated next/return_url/redirect_uri parameter",
        "parameter pollution: duplicate query/form params, array/scalar collisions",
    ),
    "cross_site": (
        "XSS: reflected, stored, DOM -- check SVG upload and any Markdown renderer",
        "CSRF: missing token, or SameSite not set",
        "CORS wildcard with credentials, or a null origin accepted",
        "host header injection in a reset link or a cache key",
        "cache poisoning via X-Forwarded-Host / X-Original-URL -> stored XSS on a cached, sensitive page",
    ),
    "business_logic": (
        "negative or zero quantities/amounts accepted",
        "coupon or discount stacking beyond the intended limit",
        "workflow step skipped by calling a later-stage endpoint directly",
        "rate limit bypass via spoofable headers or parallel accounts",
        "payment data modified in flight to a payment provider",
    ),
    "advanced": (
        "HTTP request smuggling (CL.TE / TE.CL) -> session hijack",
        "subdomain takeover via a CNAME pointing at an unclaimed cloud asset",
        "WebSocket upgrade with no auth check (CSWSH)",
        "insecure deserialization: Java, PHP, Python pickle, PHP object injection in a cookie",
        "supply-chain package-name squatting (npm/Gem/PyPI) on install",
    ),
    "infra_misconfig": (
        "exposed CI/CD (Jenkins, CircleCI, GitLab CI) with no authentication",
        "exposed monitoring (Grafana) leaking internal metrics or credentials",
        "exposed Kubernetes API with no auth -> full cluster access",
        "exposed framework actuator/debug endpoints leaking secrets or heap dumps",
    ),
    "credential_exposure": (
        "tokens embedded in a compiled app (.env inside an Electron .asar)",
        "API keys committed into a JavaScript bundle",
        "tokens leaked in CI/CD build logs",
        "hardcoded credentials in a public repository",
    ),
    "info_disclosure": (
        "stack traces or raw DB errors returned to the client",
        "GraphQL introspection left enabled in production",
        "backup files left reachable (.bak, .old, .swp, .git/)",
    ),
}

# The 6 patterns that recur across every program, every stack, every bug
# class -- worth checking before diving into program-specific detail.
UNIVERSAL_PATTERNS: tuple[str, ...] = (
    "Feature complexity = bug surface: import/export, multi-step workflows, third-party integrations, and bulk operations are where bugs concentrate.",
    "Developer inconsistency = strongest evidence: the same operation implemented two different ways (auth middleware on /v2/ but not /v1/, validation in the web UI but not the mobile API) is a signal, not a coincidence.",
    "The 'else' branch bug: fallthrough logic that grants access instead of denying it when a check doesn't clearly pass.",
    "Import/export from a URL has historically had SSRF at some point -- image import, document import, webhook registration, link unfurling.",
    "Secondary or legacy endpoints (an old /api/v1/ still live, an /internal/ path, a ?format=csv export path) often skip auth the primary path enforces.",
    "Race windows in financial or limit-bearing operations: any 'check, then act' sequence (check balance -> deduct, check coupon -> mark used) is a TOCTOU candidate.",
)

# Anti-patterns specific to a framework -- narrower and higher-signal than
# the generic vector list above, worth grepping a target's source for when
# the tech stack is known.
FRAMEWORK_ANTIPATTERNS: dict[str, tuple[str, ...]] = {
    "django_rest_framework": (
        "get_object_or_404(Model, pk=id) with no ownership check -> IDOR",
        "serializer.save(owner=request.user) where the owner field is not read-only -> mass assignment",
        "@permission_classes([IsAuthenticated]) with no object-level permission check -> IDOR",
    ),
    "express_js": (
        "req.params.id used directly in a DB query with no ownership check -> IDOR",
        "req.body.role accepted on a user-update endpoint -> privilege escalation",
        "cors({origin: true}) -> credentials-enabled CORS from any origin",
    ),
    "laravel": (
        "Model::find($id) with no team/tenant scope -> cross-tenant IDOR",
        "$request->except(['is_admin']) can be bypassed with array notation",
        "route-model binding with no policy check -> IDOR on every bound model",
    ),
    "graphql": (
        "node(id: $id) resolver with no type-specific auth -> cross-type data access",
        "a sensitive field with no @auth directive -> field-level IDOR",
        "introspection left enabled -> full schema enumeration",
    ),
    "github_actions": (
        "${{ github.event.issue.title }} interpolated into a run: block -> expression-injection RCE",
        "pull_request_target combined with actions/checkout and no explicit ref -> untrusted code execution",
        "secrets: inherit on a reusable workflow -> secret leakage to the called workflow",
    ),
}

# Patterns that produce a plausible-looking signal but are widely false
# positives -- checked before spending gate-review time on them.
COMMON_FALSE_POSITIVES: tuple[dict[str, str], ...] = (
    {
        "pattern": "missing auth returns 401 without a token",
        "reality": "401 without a token means auth IS enforced. A missing 403 for a *valid but under-privileged* token might be a finding; a bare 401 is correct behavior.",
    },
    {
        "pattern": "a parameter is reflected unmodified in the response",
        "reality": "reflection alone is not XSS -- check whether it lands in an HTML context without encoding, inside a JSON string, or in a header; context decides exploitability.",
    },
    {
        "pattern": "CORS reflects the request Origin",
        "reality": "not exploitable for credentialed data theft unless Access-Control-Allow-Credentials: true is also present.",
    },
    {
        "pattern": "a Content-Security-Policy-Report-Only header is set",
        "reality": "report-only blocks nothing; it only reports violations, and is not a finding unless the report-uri itself is attacker-controllable.",
    },
    {
        "pattern": "a rate limit was bypassed using N different source IPs",
        "reality": "not a practical attack if the harm requires far more requests than the number of IPs available makes feasible.",
    },
)

# Counter-arguments for common program pushback -- used when writing the
# rebuttal to a triager's severity downgrade, not when writing the original
# report (an overclaim in the first draft is a report-quality problem, not
# something to argue around).
SEVERITY_ESCALATION: dict[str, str] = {
    "requires authentication": "authentication requires only a free account -- no special role, no approval, no payment; the program's threat model includes malicious authenticated users.",
    "the impact is limited to one user": "the attack is repeatable against every user; this is not one victim, it's the entire user base.",
    "this is by design": "please point to documentation stating this behavior is intended -- an undocumented capability is not a documented design decision.",
    "the CVSS score is lower": "CVSS does not capture business context; quantify the actual business impact (data type, dollar amount, user count) alongside the score.",
    "we already know about this": "ask for the internal ticket ID or a previous report number -- disclosed reports were searched and none matched.",
    "this is informational": "point back to the PoC demonstrating actual impact -- informational findings don't have demonstrable impact, and this one does.",
}

# Impact tiers (supervisor.md Gate 1) -- a floor, not a ceiling: a finding
# can score higher than its tier's floor on CVSS, never lower.
IMPACT_TIERS: tuple[dict[str, object], ...] = (
    {"tier": "T0", "meaning": "critical", "examples": "RCE, auth bypass to admin, cloud credential theft, fund drain", "severity_floor": "critical (9.0+)"},
    {"tier": "T1", "meaning": "high", "examples": "PII/PHI exposure, account takeover, financial manipulation, data destruction", "severity_floor": "high (7.0+)"},
    {"tier": "T2", "meaning": "medium", "examples": "non-sensitive data exposure, read-only non-PII IDOR, stored XSS on a low-value page", "severity_floor": "medium (4.0+)"},
    {"tier": "T3", "meaning": "low", "examples": "non-sensitive info disclosure, missing security headers, clickjacking on a static page", "severity_floor": "low (0.1+)"},
    {"tier": "T4", "meaning": "none -- do not report", "examples": "CSP report-only, banner/version without an exploit, self-XSS, logout CSRF", "severity_floor": "informational (0.0)"},
)

# Report-quality formulas and rules. Plain reference text -- code cannot
# enforce a title's wording or a sentence's tone, only surface the rule so
# whoever writes the report (an AI or a human) follows it deliberately.
TITLE_FORMULA = "[Bug Class] in [Exact Endpoint/Feature] allows [attacker role] to [impact] [victim scope]"
TITLE_FORMULA_EXAMPLES: dict[str, str] = {
    "good": "IDOR in /api/v2/invoices/{id} allows authenticated user to read any customer's invoice data",
    "bad": "IDOR vulnerability found",
}

IMPACT_STATEMENT_FORMULA = (
    "An [attacker with X access level] can [exact action] by [method], resulting in [business harm]. "
    "This requires [prerequisites] and leaves [detection/reversibility]."
)

# The 60-second pass right before submitting -- distinct from
# PRESUBMISSION_NAMES (gates.py), which is the 4-item structural checklist
# a reviewer explicitly attests to; this is the finer-grained format pass.
PRESUBMIT_CHECKLIST: tuple[str, ...] = (
    "Title follows the formula: [Class] in [endpoint] allows [actor] to [impact]",
    "First sentence states the exact impact in plain English",
    "Steps to Reproduce has an exact, copy-paste-ready HTTP request",
    "A response showing the bug is included (screenshot or response body)",
    "Two test accounts were used, not just one account testing itself",
    "CVSS score is calculated and included",
    "Recommended fix is one sentence, not a lecture",
    "No typos in the endpoint path or parameter names",
    "Report is under 600 words -- triagers skim long reports",
    "Claimed severity matches the impact actually described",
)

# Writing-style rules for the report prose itself -- code cannot rewrite an
# AI's sentence for it, only name the rule so it's followed on the way in,
# not fixed on the way out.
TONE_RULES: tuple[str, ...] = (
    "No hedging: never write 'may', 'could potentially', 'it is possible that' -- if the evidence supports it, state it as fact.",
    "Present tense throughout.",
    "Start sentences with the impact, not the vulnerability name.",
    "Write like explaining to a competent developer, not a textbook.",
    "One concrete example beats three abstract sentences.",
    "No em dashes, and no 'comprehensive' / 'leverage' / 'seamless' / 'ensure'.",
    "No tables, no collapsible sections, no emoji in the report body.",
)

__all__ = [
    "ALWAYS_REJECTED",
    "SAFE_PATTERNS",
    "ATTACK_VECTORS",
    "UNIVERSAL_PATTERNS",
    "FRAMEWORK_ANTIPATTERNS",
    "COMMON_FALSE_POSITIVES",
    "SEVERITY_ESCALATION",
    "IMPACT_TIERS",
    "TITLE_FORMULA",
    "TITLE_FORMULA_EXAMPLES",
    "IMPACT_STATEMENT_FORMULA",
    "PRESUBMIT_CHECKLIST",
    "TONE_RULES",
]
