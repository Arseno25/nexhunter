You are a senior Python architect, security engineer, MCP developer, and application security reviewer.

Your task is to upgrade the existing NexHunter repository by studying its current implementation and using HexStrike AI only as a product and feature reference.

Repositories:

NexHunter:
https://github.com/Arseno25/nexhunter

Reference project:
https://github.com/0x4m4/hexstrike-ai

The goal is not to clone HexStrike AI.

The goal is to make NexHunter a safer, more modular, maintainable, auditable, and production-oriented alternative with a clear product identity:

> NexHunter is a policy-driven, secure-by-default AI security orchestration platform for authorized security assessments.

Work directly in the existing NexHunter repository.

Do not rewrite the whole repository from scratch unless a component is fundamentally unsafe or impossible to maintain.

---

# Main objective

Upgrade NexHunter so that it keeps its modular architecture while gaining the strongest product features found in HexStrike AI.

NexHunter should be better than HexStrike AI in:

* secure command execution
* modular architecture
* typed tool definitions
* authentication
* authorization
* engagement scope enforcement
* risk-based execution policy
* auditability
* test quality
* process isolation
* maintainability
* documentation accuracy

NexHunter should approach HexStrike AI in:

* MCP usability
* AI client integrations
* execution monitoring
* tool availability checks
* workflow visibility
* target profiling
* tool documentation
* onboarding experience
* dashboard readiness
* structured security assessment output

Do not compete only by increasing the number of registered tools.

Prioritize making 20–30 core tools reliable, secure, parsed, documented, and tested.

---

# Mandatory initial analysis

Before modifying code:

1. Inspect the complete NexHunter repository.
2. Inspect the relevant architecture and features of HexStrike AI.
3. Compare:

   * repository structure
   * command execution
   * process management
   * MCP implementation
   * API architecture
   * tool registration
   * agents
   * workflows
   * target profiling
   * findings
   * telemetry
   * file handling
   * caching
   * testing
   * packaging
   * documentation
4. Identify which HexStrike features are useful.
5. Identify which HexStrike implementation patterns are unsafe or unmaintainable.
6. Create an implementation plan.
7. Store the comparison in:

```text
docs/HEXSTRIKE_COMPARISON.md
```

The comparison document must include:

```markdown
# NexHunter and HexStrike AI Comparison

## Executive Summary

## Architecture Comparison

## Security Comparison

## MCP Comparison

## API Comparison

## Tool Integration Comparison

## Process Management Comparison

## Agent and Workflow Comparison

## Testing Comparison

## Documentation Comparison

## Features Worth Adopting

## Patterns That Must Not Be Copied

## NexHunter Differentiators

## Implementation Priorities
```

Do not rely only on repository README claims. Verify features against source code.

---

# Product positioning

Update NexHunter around this product identity:

```text
NexHunter
Policy-Driven AI Security Orchestration
```

Core positioning:

* local-first
* secure by default
* authorized assessments only
* modular architecture
* deterministic execution policy
* AI-compatible, but policy-controlled
* structured findings
* auditable executions
* MCP-ready
* suitable for security teams, researchers, and authorized pentesters

Do not market NexHunter as an autonomous hacking platform.

Do not use exaggerated claims such as:

* fully autonomous
* production ready
* unbreakable
* 100% safe
* 100% test coverage
* complete integration for all tools

unless those claims are proven.

---

# Architecture requirements

Keep NexHunter modular.

Move toward this architecture:

```text
src/nexhunter/
├── api/
│   ├── routes/
│   ├── middleware/
│   ├── schemas/
│   └── dependencies/
├── mcp/
│   ├── server.py
│   ├── profiles.py
│   ├── registry.py
│   └── resources.py
├── agents/
│   ├── planner.py
│   ├── profiler.py
│   ├── analyzer.py
│   └── base.py
├── workflows/
│   ├── recon.py
│   ├── web.py
│   ├── api_security.py
│   ├── code_security.py
│   └── cloud.py
├── tools/
│   ├── registry.py
│   ├── schemas.py
│   ├── definitions/
│   ├── parsers/
│   └── availability.py
├── execution/
│   ├── executor.py
│   ├── process_manager.py
│   ├── workspace.py
│   ├── isolation.py
│   └── models.py
├── security/
│   ├── authentication.py
│   ├── authorization.py
│   ├── policy.py
│   ├── scope.py
│   ├── redaction.py
│   └── audit.py
├── findings/
│   ├── models.py
│   ├── normalizer.py
│   ├── deduplication.py
│   └── correlation.py
├── engagements/
│   ├── models.py
│   ├── service.py
│   └── validation.py
├── storage/
├── telemetry/
├── cli/
├── config.py
└── exceptions.py
```

Do not create giant modules.

Guidelines:

* keep most modules focused
* avoid god classes
* avoid global mutable managers
* avoid duplicating execution logic
* avoid duplicating authentication checks
* avoid defining hundreds of MCP functions manually
* generate MCP tools from typed registry definitions where practical

No single module should become comparable to HexStrike AI's large monolithic server.

Split modules when their responsibilities become mixed or difficult to test.

---

# Critical security update

## Remove arbitrary command execution

NexHunter must not accept raw operating-system commands through REST API, MCP, agent output, CLI remote mode, or workflow input.

Remove or disable structures such as:

```json
{
  "cmd": "python -c ..."
}
```

Only registered tools may execute:

```json
{
  "tool": "nmap_scan",
  "params": {
    "target": "example.com"
  },
  "engagement_id": "ENG-001"
}
```

Requirements:

* do not use `shell=True`
* do not execute arbitrary executable names
* do not accept generic command strings
* do not accept unrestricted `additional_args`
* reject unknown tools
* reject unexpected parameters
* validate all parameters before command construction
* use argument arrays
* record every execution in the audit log

Add regression tests proving raw command execution is impossible.

---

# Authentication and authorization

Add bearer-token authentication to sensitive APIs.

Suggested environment variables:

```env
NEXHUNTER_API_TOKEN=
NEXHUNTER_BIND_HOST=127.0.0.1
NEXHUNTER_BIND_PORT=8888
NEXHUNTER_EXTERNAL_BIND_ALLOWED=false
NEXHUNTER_ENVIRONMENT=development
```

Public endpoints may include:

```text
GET /health
GET /version
GET /ready
```

All other endpoints must require authentication unless explicitly documented.

Implement permissions:

```text
read
tools:list
scan:passive
scan:active
scan:intrusive
process:read
process:terminate
findings:read
engagements:manage
admin
```

Requirements:

* constant-time token comparison
* never log tokens
* return `401` for invalid authentication
* return `403` for insufficient permissions
* fail closed in production
* block external binding unless explicitly enabled
* print a warning when binding outside loopback
* add tests for all authentication states

Design the authentication system so it can later support multiple users or API keys.

---

# Authorized engagement model

Introduce a first-class engagement model.

Suggested structure:

```json
{
  "id": "ENG-2026-001",
  "name": "Example Security Assessment",
  "status": "active",
  "allowed_targets": [
    "example.com",
    "*.staging.example.com",
    "192.168.10.0/24"
  ],
  "denied_targets": [
    "production.example.com"
  ],
  "allowed_ports": [
    "80",
    "443",
    "8000-9000"
  ],
  "allowed_protocols": [
    "http",
    "https",
    "tcp"
  ],
  "allowed_risk_levels": [
    "passive",
    "active"
  ],
  "starts_at": "2026-08-01T00:00:00Z",
  "expires_at": "2026-08-31T23:59:59Z"
}
```

Every active execution must have an engagement ID.

Implement enforcement for:

* hostname
* domain wildcard
* IPv4
* IPv6
* CIDR
* URL
* port
* protocol
* engagement validity period
* risk level
* denied scope

Denied scope must override allowed scope.

Protect against:

* loopback access
* link-local addresses
* multicast
* private networks
* cloud metadata endpoints
* DNS rebinding
* redirects outside scope
* hostnames resolving to unauthorized IP addresses

Private or local targets may be allowed only when explicitly included in the engagement.

Store the engagement ID with:

* executions
* process records
* findings
* artifacts
* telemetry
* audit logs
* workflow runs

Add extensive scope-validation tests.

---

# Policy-driven execution

Create a centralized deterministic policy engine.

Tool risk categories:

```text
passive
active
intrusive
destructive
```

Suggested behavior:

```text
Passive:
- valid authentication
- valid target scope

Active:
- valid authentication
- active-scan permission
- valid engagement
- explicit active risk allowance

Intrusive:
- intrusive permission
- valid engagement
- structured approval record

Destructive:
- disabled by default
- administrator permission
- explicit feature flag
- explicit approval record
```

Tools involving these activities must never run automatically:

* credential attacks
* brute-force operations
* payload generation
* exploitation
* persistence
* data modification
* metadata deletion
* file deletion
* denial-of-service behavior
* wireless deauthentication
* destructive cloud actions

Create:

```python
@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    required_permission: str | None = None
    requires_approval: bool = False
    policy_code: str | None = None
```

The AI layer must never override the policy engine.

Treat all model-generated output as untrusted input.

---

# Typed tool registry

Improve the current `ToolSpec` architecture rather than replacing it with manual endpoint definitions.

Each tool definition should include:

```python
@dataclass(frozen=True)
class ToolSpec:
    name: str
    display_name: str
    description: str
    category: str
    binary: str
    parameters: tuple[ParamSpec, ...]
    risk_level: RiskLevel
    timeout_seconds: int
    requires_scope: bool
    requires_approval: bool
    destructive: bool
    network_access: bool
    filesystem_access: bool
    supported_platforms: tuple[str, ...]
    supported_versions: str | None
    cache_policy: str
    parser: str | None
```

Create typed parameter schemas supporting:

```text
string
boolean
integer
enum
hostname
ip_address
cidr
url
port
port_range
file
directory
wordlist
duration
```

Validation requirements:

* reject unknown parameters
* reject missing required parameters
* reject null bytes
* reject path traversal
* reject invalid URLs
* reject unsafe schemes
* reject invalid ports
* reject excessive input lengths
* reject command option injection
* normalize domains and URLs
* resolve file paths safely
* restrict files to approved workspaces
* redact sensitive values

Do not allow generic patterns such as:

```python
["aws"] + params["command"].split()
["kubectl"] + params["command"].split()
["docker"] + params["command"].split()
```

Replace them with fixed actions:

```text
aws_get_caller_identity
aws_list_s3_buckets
kubectl_get_namespaces
kubectl_get_pods
docker_list_containers
docker_inspect_container
```

---

# Stable tool profiles

Do not expose all tools as equally mature.

Add maturity levels:

```text
stable
beta
experimental
disabled
```

Prioritize stable support for approximately 20–30 tools.

Recommended initial stable set:

```text
nmap
httpx
nuclei
subfinder
dnsx
naabu
katana
semgrep
trivy
gitleaks
nikto
whatweb
testssl.sh
ffuf
gobuster
whois
dig
curl
wpscan
sqlmap-safe-detection-profile
OWASP ZAP passive scan
```

For each stable integration provide:

* typed parameters
* safe command builder
* tool availability check
* version detection
* timeout
* structured output
* parser fixture
* normalized findings
* error handling
* compatibility notes
* risk level
* documentation
* tests

Do not automatically install external binaries.

---

# MCP improvements inspired by HexStrike AI

Improve MCP onboarding and usability without creating a giant manually maintained MCP file.

Generate MCP tools from the central tool registry where possible.

Add MCP profiles:

```text
nexhunter-core
nexhunter-recon
nexhunter-web
nexhunter-api
nexhunter-code
nexhunter-cloud
nexhunter-container
nexhunter-forensics
```

A profile must expose only relevant capabilities.

Do not expose all tools to every AI client by default.

Benefits:

* smaller MCP initialization payload
* reduced token usage
* clearer tool selection
* reduced accidental execution
* simpler permissions
* better client compatibility

Add MCP resources such as:

```text
nexhunter://tools
nexhunter://tools/stable
nexhunter://engagements
nexhunter://executions
nexhunter://findings
nexhunter://profiles
nexhunter://system/status
```

Add MCP prompts or workflow templates only when useful.

Document MCP configuration for:

* Claude Desktop
* Claude Code
* Cursor
* VS Code
* Roo Code
* OpenCode
* other standard MCP clients

Store documentation in:

```text
docs/mcp/
├── claude-desktop.md
├── claude-code.md
├── cursor.md
├── vscode.md
├── roo-code.md
└── opencode.md
```

Do not manually duplicate business logic between REST API and MCP.

Both interfaces must call the same service layer.

---

# Execution and process management

Build a reliable execution service inspired by HexStrike's process visibility but with stronger safety.

Every execution must have an internal UUID.

Process states:

```text
queued
validating
authorized
running
completed
failed
timed_out
terminated
blocked
```

Execution record:

```python
@dataclass
class ExecutionRecord:
    id: str
    request_id: str
    engagement_id: str
    tool_name: str
    status: ExecutionStatus
    target: str | None
    redacted_parameters: dict
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    exit_code: int | None
    error_code: str | None
    workspace_path: str
```

Requirements:

* use argument arrays
* use `shell=False`
* isolated workspace per execution
* output-size limits
* stdout and stderr captured separately
* process-group termination
* graceful timeout termination
* forced kill after grace period
* child-process cleanup
* workspace cleanup policy
* safe artifact retention
* redacted arguments
* platform-aware process handling
* concurrency-safe process registry

Add API endpoints:

```text
GET  /api/executions
GET  /api/executions/{id}
GET  /api/executions/{id}/output
POST /api/executions/{id}/terminate
GET  /api/executions/{id}/artifacts
```

Do not expose raw operating-system process IDs as the main API identifier.

Optionally add server-sent events or WebSocket output streaming, but only after authentication and authorization are enforced.

---

# Execution dashboard readiness

Prepare backend schemas for a future web dashboard.

The API should expose structured data for:

* running executions
* completed scans
* failed tools
* execution duration
* output preview
* engagement
* risk level
* policy decision
* findings count
* generated artifacts
* tool availability
* system health

Do not build a large frontend unless the repository already includes one.

Create API contracts and documentation first.

---

# Tool doctor

Add a CLI command:

```bash
nexhunter doctor
```

It should check:

* NexHunter version
* Python version
* supported operating system
* writable data directory
* workspace permissions
* API token configuration
* external binding status
* dependency availability
* stable tool binaries
* binary versions
* MCP configuration readiness
* database readiness
* process execution capability

Example output:

```text
NexHunter Doctor

Core
[OK] Python 3.12
[OK] Configuration loaded
[OK] Workspace writable
[WARN] API token not configured
[OK] Server bound to loopback

Stable tools
[OK] nmap 7.95
[OK] httpx 1.7.1
[MISSING] nuclei
[MISSING] semgrep

Security
[OK] Raw command execution disabled
[OK] External binding disabled
[OK] Destructive tools disabled
```

Also add:

```bash
nexhunter tools list
nexhunter tools check
nexhunter tools info nmap_scan
nexhunter mcp profiles
nexhunter engagements validate <file>
```

---

# Target profiler

Implement a safe target profiling service inspired by HexStrike AI.

The profiler should collect structured observations from approved passive or active tools.

Example:

```json
{
  "target": "example.com",
  "target_type": "web_application",
  "resolved_addresses": [
    "203.0.113.10"
  ],
  "technologies": [
    {
      "name": "nginx",
      "confidence": 0.9,
      "source": "httpx"
    }
  ],
  "services": [
    {
      "port": 443,
      "protocol": "https",
      "service": "nginx",
      "source": "nmap"
    }
  ],
  "observations": [],
  "recommended_safe_workflows": [
    "web-passive"
  ]
}
```

Requirements:

* every value must include evidence or source
* do not invent technologies
* do not invent vulnerabilities
* distinguish observed and inferred values
* include confidence only when justifiable
* apply engagement scope to every profiling action
* store profiler output with the engagement

---

# Workflow improvements

Add structured workflows with visible phases.

Recommended workflows:

```text
recon-passive
recon-active
web-passive
web-standard
api-security
code-security
dependency-security
container-security
cloud-posture-readonly
```

Each workflow must define:

```python
@dataclass(frozen=True)
class WorkflowDefinition:
    name: str
    description: str
    phases: tuple[WorkflowPhase, ...]
    required_permissions: tuple[str, ...]
    maximum_risk_level: RiskLevel
    required_tools: tuple[str, ...]
```

Workflow execution must return:

```json
{
  "workflow_id": "...",
  "name": "web-standard",
  "status": "running",
  "current_phase": "technology_detection",
  "progress": 40,
  "executions": [],
  "findings": [],
  "errors": []
}
```

The AI may recommend a workflow, but the policy engine must validate it.

---

# Finding normalization and correlation

Implement a consistent finding model:

```python
@dataclass
class Finding:
    id: str
    engagement_id: str
    execution_id: str
    tool: str
    target: str
    category: str
    title: str
    description: str
    severity: str
    confidence: str
    evidence: dict
    remediation: str | None
    references: list[str]
    cve_ids: list[str]
    cwe_ids: list[str]
    cvss_score: float | None
    fingerprint: str
    first_seen_at: datetime
    last_seen_at: datetime
```

Requirements:

* use SHA-256 fingerprints
* redact secrets from evidence
* normalize severity
* distinguish observation from vulnerability
* distinguish parser failure from finding
* preserve raw output as a separate artifact
* avoid duplicate findings
* do not invent CVEs
* do not invent CVSS scores
* do not invent remediation from unsupported evidence

Add export formats:

```text
JSON
JSONL
Markdown
HTML
SARIF
```

SARIF should be used primarily for code and dependency findings when applicable.

---

# Caching improvements

Do not cache raw command strings.

Generate canonical cache keys from:

```json
{
  "engagement_id": "ENG-001",
  "tool": "nmap_scan",
  "tool_version": "7.95",
  "params": {
    "target": "example.com",
    "ports": "80,443"
  }
}
```

Hash canonical JSON using SHA-256.

Requirements:

* redact sensitive parameters
* per-engagement isolation
* configurable TTL
* size limit
* concurrency-safe eviction
* no caching for state-changing tools
* no caching for credential attacks
* no caching for destructive tools
* tool-specific cache policy

---

# Audit logs and telemetry

Separate audit logs from operational telemetry.

Audit fields:

```text
timestamp
request_id
identity
source_ip
engagement_id
action
tool
target
risk_level
policy_decision
execution_id
status
redacted_parameters
```

Requirements:

* structured JSON logs
* log rotation
* no tokens
* no cookies
* no passwords
* no secrets
* no full credential-bearing URLs
* request ID in every API response
* audit denied executions
* audit process termination
* audit engagement changes
* audit administrative changes

Telemetry should track:

* execution duration
* success rate
* timeout rate
* parser failures
* unavailable binaries
* active executions
* cache hits
* cache misses

Do not keep unlimited telemetry in memory.

---

# File and artifact safety

Do not copy HexStrike's generic file manager API.

NexHunter must not expose arbitrary file creation, modification, listing, or deletion.

All artifacts must remain inside:

```text
NEXHUNTER_DATA_DIR/
  engagements/
    <engagement_id>/
      executions/
        <execution_id>/
```

Requirements:

* canonicalize paths
* block path traversal
* block symlink escape
* block absolute user-supplied paths unless explicitly allowed
* validate artifact names
* limit file sizes
* restrict downloadable artifacts by engagement permission
* redact sensitive artifacts where necessary
* apply retention rules

Do not allow AI-generated paths to bypass the workspace.

---

# API improvements

Use FastAPI if migration materially improves:

* validation
* OpenAPI
* authentication dependencies
* structured schemas
* testing
* lifecycle management

Preserve endpoint compatibility where reasonable.

Add:

```text
GET  /health
GET  /ready
GET  /version

GET  /api/tools
GET  /api/tools/{name}
GET  /api/tools/status

POST /api/engagements
GET  /api/engagements
GET  /api/engagements/{id}

POST /api/executions
GET  /api/executions
GET  /api/executions/{id}
POST /api/executions/{id}/terminate

POST /api/workflows
GET  /api/workflows
GET  /api/workflows/{id}

GET  /api/findings
GET  /api/findings/{id}
```

Requirements:

* request-body size limits
* content-type validation
* rate limiting
* consistent error schema
* no stack-trace leakage
* safe CORS default
* authenticated docs when externally exposed
* loopback default binding
* external binding warning

Error structure:

```json
{
  "ok": false,
  "error": {
    "code": "TARGET_OUT_OF_SCOPE",
    "message": "The requested target is outside the authorized engagement scope.",
    "details": {}
  },
  "request_id": "..."
}
```

---

# Configuration

Create typed configuration.

Suggested variables:

```env
NEXHUNTER_ENVIRONMENT=development
NEXHUNTER_API_TOKEN=
NEXHUNTER_BIND_HOST=127.0.0.1
NEXHUNTER_BIND_PORT=8888
NEXHUNTER_EXTERNAL_BIND_ALLOWED=false

NEXHUNTER_DATA_DIR=
NEXHUNTER_LOG_LEVEL=INFO
NEXHUNTER_AUDIT_LOG_PATH=
NEXHUNTER_MAX_REQUEST_BYTES=1048576
NEXHUNTER_MAX_OUTPUT_BYTES=10485760
NEXHUNTER_DEFAULT_TIMEOUT=300
NEXHUNTER_PROCESS_TERMINATION_GRACE=5

NEXHUNTER_CACHE_ENABLED=true
NEXHUNTER_CACHE_TTL=600
NEXHUNTER_CACHE_MAX_ENTRIES=1000

NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED=false
NEXHUNTER_INTRUSIVE_TOOLS_ENABLED=false
```

Add `.env.example`.

Validate configuration at startup.

Never silently fall back to unsafe values.

---

# Packaging

Modernize the project using `pyproject.toml`.

Requirements:

* `src/` layout
* project metadata
* Python version constraints
* runtime dependencies
* optional dependency groups
* console scripts
* editable installation
* build validation

Expected commands:

```bash
pip install -e .
nexhunter server
nexhunter mcp
nexhunter doctor
nexhunter tools list
```

Suggested optional dependencies:

```text
api
mcp
dev
reports
```

Do not force browser automation or heavy optional dependencies into the minimal install unless required.

---

# Testing

Replace weak tests and false-positive patterns.

A test must fail through assertion failure or raised exception.

Never write tests such as:

```python
assert result["ok"] or not result["ok"]
```

Never return `False` from a pytest test and treat it as failure.

Add tests for:

## Security

* raw command rejected
* unknown executable rejected
* `shell=True` not used
* shell metacharacters remain inert
* additional argument injection rejected
* option injection rejected
* path traversal rejected
* symlink escape rejected
* null byte rejected
* metadata IP blocked
* loopback blocked unless scoped
* DNS resolution checked
* redirect destination checked
* unauthorized target rejected
* expired engagement rejected
* denied target overrides allowed wildcard
* sensitive values redacted

## Authentication

* missing token
* invalid token
* valid token
* missing permission
* admin permission
* external binding configuration

## Execution

* successful command
* unavailable binary
* timeout
* child process termination
* output limit
* stderr capture
* process lookup
* process termination
* invalid state transition
* concurrent state access

## Registry

* typed parameter validation
* unknown parameter
* required parameter
* enum validation
* URL validation
* IP validation
* CIDR validation
* port validation
* file validation
* stable tool metadata

## MCP

* profile filtering
* registry generation
* unauthorized tool call
* invalid parameters
* policy enforcement
* MCP and REST consistency

## Findings

* parser fixtures
* severity normalization
* fingerprint stability
* deduplication
* redaction
* SARIF export
* Markdown export

Use mocked binaries and fixture scripts.

Do not run intrusive scans in normal CI.

Measure coverage:

```bash
pytest --cov=src/nexhunter --cov-report=term-missing --cov-report=xml
```

Set a realistic threshold of at least 80%.

Do not claim 100% unless measured.

---

# CI

Add GitHub Actions for:

```text
Ruff lint
Ruff formatting check
mypy
Bandit
pytest
coverage
pip-audit
package build
```

Test supported Python versions.

Do not require external offensive tools in regular CI.

Add optional tool integration workflows if necessary.

---

# Documentation improvements inspired by HexStrike

HexStrike has stronger onboarding and presentation. Improve NexHunter documentation without copying its unsafe architecture or unsupported marketing claims.

Add:

```text
README.md
SECURITY.md
CONTRIBUTING.md
CHANGELOG.md
LICENSE
.env.example

docs/
├── architecture.md
├── security-model.md
├── engagement-scope.md
├── tool-registry.md
├── tool-development.md
├── execution-model.md
├── deployment.md
├── API.md
├── workflows.md
├── findings.md
├── HEXSTRIKE_COMPARISON.md
├── UPGRADE_REPORT.md
└── mcp/
```

README should contain:

* clear product description
* legal-use warning
* architecture diagram
* feature overview
* installation
* quick start
* CLI commands
* MCP setup
* API example
* stable tools table
* experimental tools table
* security model
* limitations
* roadmap
* contribution guide

Include this warning prominently:

> Only use NexHunter against systems you own or are explicitly authorized to assess.

Clearly distinguish:

```text
Registered tools
Stable integrations
Beta integrations
Experimental integrations
Unavailable tools
```

---

# Features to adopt from HexStrike AI

Implement the product value, not the unsafe implementation.

Adopt or improve:

1. MCP client onboarding.
2. Tool availability dashboard.
3. Tool version detection.
4. Process visibility.
5. Execution output streaming.
6. Execution termination.
7. Target profiling.
8. Structured workflows.
9. Workflow progress.
10. Finding correlation.
11. Tool categories.
12. Tool usage documentation.
13. System status endpoint.
14. Troubleshooting documentation.
15. Rich CLI status output.
16. API examples.
17. MCP profile support.
18. Security assessment summaries.
19. Failure and timeout visibility.
20. Optional dashboard-ready API.

---

# Patterns that must not be copied from HexStrike AI

Do not copy these patterns:

1. Giant monolithic server modules.
2. Giant monolithic MCP modules.
3. `shell=True`.
4. Arbitrary command API.
5. Generic file-manager API.
6. Unauthenticated sensitive endpoints.
7. Generic unrestricted `additional_args`.
8. String-based command construction.
9. Tool-specific logic duplicated across hundreds of endpoints.
10. Marketing claims without reproducible evidence.
11. Global mutable application state without synchronization.
12. AI output directly controlling the operating system.
13. Generic cloud CLI command passthrough.
14. Generic Docker or Kubernetes command passthrough.
15. Destructive tools enabled automatically.
16. Payload-generation endpoints without strict controls.
17. File write or delete operations outside isolated workspaces.
18. Mixing API, execution, parsers, tools, and UI logic in one module.

---

# Recommended implementation phases

## Phase 1 — Baseline and architecture

* run current tests
* record failures
* inspect imports and dependencies
* modernize packaging
* create architecture documents
* create HexStrike comparison document

## Phase 2 — Security foundation

* remove raw command execution
* introduce typed configuration
* add authentication
* add permissions
* implement engagement scope
* implement policy engine
* implement secret redaction

## Phase 3 — Execution layer

* create isolated workspaces
* refactor process execution
* add process states
* add timeout cleanup
* add output limits
* add audit records
* protect shared state

## Phase 4 — Tool registry

* implement typed parameters
* add maturity levels
* classify risk levels
* remove generic CLI passthrough
* stabilize 20–30 core tools
* add availability and version checks

## Phase 5 — API and MCP

* unify service layer
* improve REST API
* add MCP profiles
* generate MCP tools from registry
* document client configurations

## Phase 6 — Findings and workflows

* normalize findings
* add structured workflows
* add target profiler
* add exports
* add correlation

## Phase 7 — Testing and CI

* replace weak tests
* add security regression tests
* add parser fixtures
* add concurrency tests
* enforce coverage threshold
* add CI security checks

## Phase 8 — Documentation and release preparation

* update README
* add migration guide
* add deployment guide
* add security model
* create upgrade report
* verify all claims

---

# Acceptance criteria

The work is complete only when:

* arbitrary command execution is removed
* no execution path uses `shell=True`
* sensitive endpoints require authentication
* permissions are enforced
* engagement scope is enforced
* denied targets override allowed targets
* cloud metadata endpoints are blocked by default
* tool parameters are typed and validated
* generic command passthrough is removed
* intrusive tools require explicit approval
* destructive tools are disabled by default
* AI output cannot bypass policy
* process timeouts terminate child processes
* execution state is reliable
* secrets are redacted
* workspaces prevent path traversal
* shared state is concurrency-safe
* stable tools have parsers and tests
* MCP tools support profiles
* REST and MCP share the same service layer
* target profiler produces evidence-based output
* findings are normalized
* test coverage is measured honestly
* CI passes
* documentation matches implementation
* `docs/HEXSTRIKE_COMPARISON.md` exists
* `docs/UPGRADE_REPORT.md` exists
* the project installs with `pip install -e .`
* CLI commands work
* no new critical or high-severity vulnerability is introduced

---

# Required final report

Create:

```text
docs/UPGRADE_REPORT.md
```

Use this structure:

```markdown
# NexHunter Upgrade Report

## Executive Summary

## Original Architecture

## Original Security Issues

## HexStrike AI Comparison

## Features Adopted

## Patterns Intentionally Rejected

## New Architecture

## Authentication and Authorization

## Engagement Scope

## Policy Engine

## Execution Security

## Tool Registry Changes

## Stable Tool Integrations

## MCP Changes

## API Changes

## Workflow Changes

## Finding Model Changes

## Testing Results

## Coverage Results

## CI Results

## Breaking Changes

## Migration Guide

## Environment Variables

## Installation and Usage

## Remaining Risks

## Recommended Next Phase
```

Include actual commands executed and actual test results.

Do not fabricate results.

---

# Working rules

1. Inspect before editing.
2. Do not wait for confirmation unless a decision cannot be made safely.
3. Make small, logical changes.
4. Run tests after each major change.
5. Fix regressions immediately.
6. Do not hide exceptions.
7. Do not use broad exception handling without structured reporting.
8. Do not add offensive capabilities during this update.
9. Do not add unsafe convenience endpoints.
10. Do not weaken security for compatibility.
11. Preserve public APIs only when safe.
12. Document breaking changes.
13. Keep code typed.
14. Keep modules focused.
15. Use secure defaults.
16. Keep external binding disabled by default.
17. Do not automatically install external security binaries.
18. Do not make unsupported feature claims.
19. Do not copy source code from HexStrike AI.
20. HexStrike AI is a feature reference, not an implementation template.

Start by inspecting both repositories and writing:

```text
docs/HEXSTRIKE_COMPARISON.md
```

Then create an implementation plan and begin with the highest-severity NexHunter security issues.
