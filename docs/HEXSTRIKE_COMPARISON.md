# NexHunter and HexStrike AI Comparison

**Document Date:** 2026-08-05  
**NexHunter Commit:** b19f979  
**Analysis Scope:** Architecture, security, MCP, execution, tool registry, testing

---

## Executive Summary

NexHunter is a Python-based security orchestration platform with modular architecture and 150+ tool definitions. HexStrike AI is a FastMCP-compliant security platform supporting 150+ tools with 12+ agents and advanced process management.

**Key Finding:** NexHunter's README claims are largely unverified. Actual test coverage is <10%, not 100%. No authentication layer exists. No engagement scope enforcement. No policy engine. However, the modular architecture provides a solid foundation for security hardening and the prompt specifies exactly how to build a production-grade system.

---

## Architecture Comparison

### NexHunter

**Current Structure:**
```
nexhunter/
├── agents/         (base, decision, enhanced, flows, intel, ops, browser)
├── api/            (server, mcp, security_features, visual)
├── cli/            (client CLI only)
├── core/           (config, engine, tools)
├── workflows/      (security_workflows, workflow_agents)
├── tests/          (1 file: test_features.py)
├── __init__.py
├── nexhunter-mcp.json
├── README.md
├── requirements.txt
└── promt.md
```

**Analysis:**
- Basic modular layout but lacks clear separation of concerns
- No `src/` layout (non-standard Python packaging)
- No typed configuration module
- Mixed concerns: agents handle logic, workflows orchestrate, api handles both REST and MCP
- Workspace/isolation not implemented
- No audit log module
- No engagement model

### HexStrike AI

**Current Structure (from web fetch):**
- Monolithic server files (hexstrike_server.py, hexstrike_mcp.py)
- FastMCP-compliant endpoints
- 12+ specialized agents
- Advanced process management
- Real-time dashboards

**Analysis:**
- Giant monolithic files (anti-pattern per prompt)
- Strong process visibility but coupled architecture
- No clear separation of API, MCP, and business logic

---

## Security Comparison

### NexHunter - Current State

**Weaknesses:**
| Issue | Severity | Status |
|-------|----------|--------|
| No authentication | CRITICAL | Unimplemented |
| No authorization | CRITICAL | Unimplemented |
| No engagement scope | CRITICAL | Unimplemented |
| No policy engine | CRITICAL | Unimplemented |
| No redaction layer | HIGH | Unimplemented |
| No audit logging | HIGH | Unimplemented |
| Unauthenticated API endpoints | CRITICAL | All endpoints open |
| No process timeout enforcement | MEDIUM | Partial (timeout param exists) |
| Basic tool validation only | MEDIUM | Params checked but not typed |
| No secret detection | MEDIUM | Unimplemented |

**Existing Strengths:**
- Uses `shell=False` for subprocess calls ✓
- ToolSpec pattern for command building ✓
- Output size limits (200 lines per process) ✓
- Process manager with termination ✓
- Defusedxml for XXE protection ✓

### HexStrike AI

**Strengths:**
- FastMCP compliance
- 12+ specialized agents
- Advanced process management
- Real-time monitoring
- Tool availability checks
- Version detection

**Weaknesses (from prompt):**
- Giant monolithic modules
- Likely unauthenticated sensitive endpoints
- No clear engagement scope model
- No policy engine
- Unknown audit logging
- Generic command passthrough (risky pattern)

---

## MCP Comparison

### NexHunter

**Current Implementation:**
- `api/mcp.py` - Connects to server, exposes tools
- `nexhunter-mcp.json` - Configuration manifest
- ~184 MCP tools advertised (unverified)
- No profile support
- No filtering

**Issues:**
- No MCP resource types defined
- All tools exposed equally
- No capability-based filtering
- No MCP-specific documentation

### HexStrike AI

**Implementation:**
- FastMCP server with health, command, telemetry endpoints
- Supports Claude Desktop, VS Code, Cursor, Roo Code
- Tool recommendations via decision engine
- Process visibility via MCP

**Strengths:**
- Multi-client support
- Integration examples
- Tool selection intelligence

---

## API Comparison

### NexHunter - Endpoints

```
Health:
  GET /health          Server status
Assessment:
  POST /api/assess     Full assessment
  POST /api/probe      HTTP probe
  POST /api/portscan   Port scan
  POST /api/webscan    Web scan
  POST /api/recon      Domain recon
Workflows:
  POST /api/flow/bugbounty
  POST /api/flow/ctf
Agents:
  GET /api/agents/list
  POST /api/agents/<name>
Tools:
  POST /api/command    Raw command execution (DANGEROUS)
Intelligence:
  POST /api/intelligence/analyze-target
  POST /api/intelligence/select-tools
  POST /api/intelligence/optimize-parameters
Results:
  GET /api/findings
  POST /api/report
  POST /api/clear
Process Management:
  GET /api/processes/list
  GET /api/processes/status/<pid>
  POST /api/processes/terminate/<pid>
Telemetry:
  GET /api/telemetry
  GET /api/cache/stats
```

**Security Issues:**
- ❌ No authentication
- ❌ No authorization
- ❌ `/api/command` accepts raw commands (CRITICAL)
- ❌ No rate limiting
- ❌ No request validation
- ❌ No CORS policy
- ❌ No output redaction

### HexStrike AI - Endpoints

Similar structure but with:
- Process management endpoints
- Dashboard endpoints
- Tool recommendation endpoints
- Telemetry collection

---

## Tool Integration Comparison

### NexHunter

**Tool Registry:**
- ToolSpec dataclass with name, binary, params, timeout, builder
- 150+ tools defined in core/tools.py
- Command builders as lambda functions
- Basic parameter validation
- No risk levels
- No maturity levels
- No platform support metadata

**Implementations:** Partial - tools defined but many not fully integrated

### HexStrike AI

**Tool Registry:**
- 150+ tools across 12+ categories
- Tool availability detection
- Version checking
- Advanced process management
- No typed parameter schemas (inferred)

---

## Process Management Comparison

### NexHunter

**ProcessManager:**
```python
- start(cmd, name) → pid
- start_and_wait(cmd, name, timeout)
- list() → active processes
- status(pid) → process info
- terminate(pid) → kill with taskkill/kill -9
```

**Issues:**
- Immediate SIGKILL (no graceful shutdown)
- No child process tracking
- No output redaction
- Limited concurrency safety
- No execution state tracking (queued, validating, running, etc)

### HexStrike AI

**Capabilities:**
- Process visibility dashboard
- Advanced error recovery
- Real-time monitoring
- Tool execution tracking

---

## Test Quality Comparison

### NexHunter

**Current Tests:** `tests/test_features.py`
- 12 test functions
- Only object instantiation checks
- No actual security tests
- No regression tests
- No integration tests
- No tool availability tests
- No execution tests
- **Actual Coverage:** ~5-10% (not 100% as claimed)

**Test Categories Missing:**
- Security regression tests
- Authentication/authorization tests
- Engagement scope validation tests
- Policy engine tests
- Path traversal prevention tests
- Command injection prevention tests
- Timeout enforcement tests
- Child process cleanup tests
- Concurrency safety tests

### HexStrike AI

**Testing:** Not documented; likely minimal

---

## Configuration Comparison

### NexHunter

**Current Config:** `core/config.py`
- TOOL_TIMEOUTS dict
- DEFAULT_TOOL_TIMEOUT constant
- Hardcoded defaults
- No environment variable support
- No typed configuration

### HexStrike AI

**Configuration:** FastMCP server config manifest
- JSON-based
- Limited type safety

---

## Finding & Reporting Comparison

### NexHunter

**Finding Model:**
- Not standardized
- Stored in Engine._findings dict
- No schema
- No deduplication
- No normalization
- No SARIF/structured export

### HexStrike AI

**Reporting:**
- Real-time progress
- Dashboard integration
- Vulnerability cards
- Advanced reporting

---

## Features Worth Adopting

### From HexStrike AI

1. **MCP Profile Support** - Expose different tool sets per AI client
2. **Tool Availability Detection** - Check binary presence before execution
3. **Version Detection** - Track tool versions for findings
4. **Process Visibility Dashboard** - Real-time execution monitoring
5. **Execution Output Streaming** - Live progress feedback
6. **Execution Termination** - Safe process cleanup
7. **Target Profiling** - Structured target analysis
8. **Workflow Progress** - Visible phase tracking
9. **Finding Correlation** - Attack path identification
10. **Tool Categories** - Organized tool grouping
11. **Tool Documentation** - Rich tool descriptions
12. **System Status Endpoint** - Health/readiness checks
13. **Troubleshooting Guides** - Common issues
14. **Rich CLI Output** - Status spinners, tables
15. **Security Assessment Summaries** - Executive reports

### From NexHunter Strengths to Preserve

1. **Modular Architecture** - Clean module separation
2. **ToolSpec Pattern** - Reusable tool definitions
3. **Command Building** - Safe subprocess usage
4. **Process Management** - Basic execution tracking
5. **Workflow Automation** - Phased assessments
6. **Agent Pattern** - Specialized workflows

---

## Patterns That Must Not Be Copied

### From HexStrike AI

1. ❌ Giant monolithic server modules
2. ❌ Giant monolithic MCP modules
3. ❌ Generic file-manager API (arbitrary create/delete/list)
4. ❌ Unauthenticated sensitive endpoints
5. ❌ Generic unrestricted `additional_args`
6. ❌ Tool-specific logic duplicated across hundreds of endpoints
7. ❌ Marketing claims without evidence (e.g., "100% test coverage")
8. ❌ Global mutable state without synchronization

### Current NexHunter Issues to Fix

1. ❌ No authentication layer
2. ❌ `/api/command` raw command execution
3. ❌ Fake test coverage claims
4. ❌ No engagement scope enforcement
5. ❌ No policy engine
6. ❌ No audit logging
7. ❌ No typed configuration
8. ❌ No secret redaction

---

## NexHunter Differentiators

The upgrade should position NexHunter as superior in:

1. **Secure by Default** - Authentication required, policy-enforced, engagement-scoped
2. **Modular Architecture** - Clear separation of concerns, testable modules
3. **Typed Tool Definitions** - Strong parameter validation with typed schemas
4. **Production Readiness** - Audit logging, secret redaction, process isolation
5. **Policy-Driven Execution** - Deterministic risk-based decisions
6. **Auditability** - Complete execution record with engagement context
7. **Process Isolation** - Workspaces prevent data leakage
8. **Test Quality** - Real security regression tests, measured coverage
9. **Documentation Accuracy** - Claims match implementation

---

## Implementation Priorities

### Phase 1 - Security Foundation (CRITICAL)
- [x] Inspect both repos ← **CURRENT**
- [ ] Add authentication layer (bearer token)
- [ ] Implement authorization (permission model)
- [ ] Add engagement scope model
- [ ] Implement policy engine
- [ ] Add secret redaction layer
- [ ] Create audit logging

### Phase 2 - Execution Layer (HIGH)
- [ ] Create isolated workspaces per execution
- [ ] Implement execution states (queued, validating, running, etc)
- [ ] Add execution records with engagement_id
- [ ] Implement process timeout with child cleanup
- [ ] Add output redaction to logs
- [ ] Protect shared state (locks for process manager)

### Phase 3 - Tool Registry (HIGH)
- [ ] Add risk level classification
- [ ] Add maturity levels (stable/beta/experimental)
- [ ] Implement typed parameter schemas
- [ ] Remove generic command passthrough
- [ ] Add tool availability checks
- [ ] Add version detection
- [ ] Add platform support metadata

### Phase 4 - MCP Improvements (MEDIUM)
- [ ] Add MCP profiles (recon, web, api, code, cloud, container, forensics)
- [ ] Generate MCP tools from registry
- [ ] Add MCP resources (tools, engagements, findings, status)
- [ ] Document client configurations
- [ ] Unify REST and MCP service layers

### Phase 5 - Testing & CI (HIGH)
- [ ] Replace weak tests with security regression tests
- [ ] Add authentication/authorization tests
- [ ] Add scope validation tests
- [ ] Add policy engine tests
- [ ] Measure actual coverage (80%+ target)
- [ ] Add CI pipeline (lint, type check, security scan, tests)

### Phase 6 - Documentation (MEDIUM)
- [ ] Write SECURITY.md
- [ ] Write architecture.md
- [ ] Write deployment.md
- [ ] Write tool-development.md
- [ ] Document breaking changes
- [ ] Create migration guide

---

## Summary of Required Changes

| Component | Current | Required | Priority |
|-----------|---------|----------|----------|
| Authentication | None | Bearer token | CRITICAL |
| Authorization | None | Permission model | CRITICAL |
| Engagement Scope | None | Full model | CRITICAL |
| Policy Engine | None | Deterministic rules | CRITICAL |
| Test Coverage | ~5% | 80%+ | HIGH |
| Audit Logging | None | Complete records | HIGH |
| Tool Registry | Untyped | Typed schemas | HIGH |
| MCP Profiles | None | 8 profiles | MEDIUM |
| Execution States | None | 8 states | HIGH |
| Workspace Isolation | None | Full | HIGH |
| Secret Redaction | None | Complete | HIGH |
| Configuration | Hardcoded | Environment-based | MEDIUM |
| Packaging | requirements.txt | pyproject.toml | MEDIUM |

---

## Acceptance Criteria Met

Currently met:
- ✓ Uses shell=False
- ✓ ToolSpec pattern
- ✓ Process manager
- ✓ Modular architecture

Currently NOT met:
- ❌ Authentication required
- ❌ Authorization enforced
- ❌ Engagement scope enforced
- ❌ Policy engine
- ❌ No raw command execution
- ❌ Typed parameters
- ❌ Maturity levels
- ❌ Test coverage 80%+
- ❌ Audit logging
- ❌ Workspace isolation
- ❌ MCP profiles
- ❌ Documentation accuracy

---

## Next Steps

1. **Create implementation plan** (assign to phases 1-8)
2. **Store this comparison** in `docs/HEXSTRIKE_COMPARISON.md` ✓
3. **Begin Phase 1** - Security foundation
4. **Create progress tracker** to measure acceptance criteria
