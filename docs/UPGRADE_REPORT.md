# NexHunter Upgrade Report

**Baseline:** `b19f979` · **Head:** `ba2fa4f` · **Date:** 2026-08-05
**Diff:** 69 files changed, 10,014 insertions, 199 deletions

## Executive Summary

NexHunter was a capable tool orchestrator with a modular layout and no security
model. Any caller reaching the port could run any registered tool against any
target, and `/api/command` accepted a raw operating-system command string. The
README claimed 100% test coverage; the actual figure was under 10%.

This upgrade adds the missing model: authentication, permissions, engagement
scope, a deterministic policy engine, secret redaction, audit logging, isolated
execution, and MCP profiles. Both interfaces now route through one execution
path, so an AI client is a caller like any other — it may propose a tool and
parameters, but not a command, not its own scope, and not a policy override.

Three arbitrary-command surfaces were removed, five scope-validation defects
were found and fixed, and two secret leaks were found while testing. Coverage
is now **63% measured** overall and 87–100% across the security and execution
modules. That number is stated as measured rather than rounded up.

Scope enforcement is **on by default**: a fresh install with no engagement
denies every execution and tells the operator how to declare one.

**Not finished:** typed parameter schemas, finding normalization, the target
profiler, and workflow migration to the new execution layer.

## Original Architecture

```
nexhunter/
├── agents/      18 agents (decision, intel, ops, flows, enhanced, browser)
├── api/         server.py (REST), mcp.py (MCP), security_features.py, visual.py
├── cli/         client.py
├── core/        config.py, engine.py, tools.py (~164 ToolSpec entries)
├── workflows/   9 workflow definitions
└── tests/       test_features.py (12 instantiation checks)
```

Sound module boundaries. The gap was everything between "a request arrived" and
"a process started".

## Original Security Issues

| # | Issue | Severity | Status |
|---|---|---|---|
| 1 | `/api/command` executed arbitrary OS command strings | Critical | Fixed |
| 2 | 10 tools splatted a user string into argv (`["aws"] + cmd.split()`) | Critical | Fixed |
| 3 | No authentication on any endpoint | Critical | Fixed |
| 4 | No authorization or permission model | Critical | Fixed |
| 5 | No engagement scope; any target reachable | Critical | Fixed |
| 6 | No policy engine; AI output reached the OS unchecked | Critical | Fixed |
| 7 | No audit log | High | Fixed |
| 8 | No secret redaction | High | Fixed |
| 9 | Timeouts killed only the direct child, orphaning scanners | High | Fixed |
| 10 | No workspace isolation; artifacts shared one directory | High | Fixed |
| 11 | Unsynchronized shared process state under a threaded server | Medium | Fixed |
| 12 | False "100% test coverage" claim | Medium | Fixed |
| 13 | `requirements.txt` only; no installable package | Medium | Fixed |

### Issue 1 — the raw command API

```python
cmd = shlex.split(body.get("cmd", ""))   # removed
return PM.start_and_wait(cmd, cmd[0], timeout)
```

Anything reaching the port, including a model, chose what ran.

### Issue 2 — passthroughs wearing a tool's name

```python
"aws_cli": ToolSpec(params={"command": "s3 ls"},
                    builder=lambda p: ["aws"] + p["command"].split())
```

Removing the raw endpoint alone would have left this open: `s3 ls` and
`iam create-access-key` were the same tool. Fixed by replacing all ten with
enumerated read-only actions, and by a regression test that rejects any future
builder that splits a parameter into argv.

## HexStrike AI Comparison

See [HEXSTRIKE_COMPARISON.md](HEXSTRIKE_COMPARISON.md).

**Adopted (the product value):** MCP client onboarding, tool availability and
version detection, process visibility, execution termination, tool categories,
system status, rich CLI status output, MCP profile support.

**Rejected (the implementation):** monolithic server and MCP modules,
`shell=True`, the arbitrary-command API, the generic file-manager API,
unauthenticated sensitive endpoints, unrestricted `additional_args`,
string-based command construction, generic cloud/Docker/Kubernetes passthrough,
and marketing claims without evidence.

## New Architecture

Added `security/` and `execution/`; existing packages kept.

```
security/     authentication · authorization · engagement · policy
              redaction · audit · enforcement (SecurityGate)
execution/    models (state machine) · workspace · runner · registry · service
core/         tools (+ category, maturity, describe) · availability
api/          mcp_profiles · server (+ tools and execution endpoints)
cli/          doctor · registry · profiles · engagement validate
```

Every caller enters through `ExecutionService`. Diagrams in
[architecture.md](architecture.md).

## Authentication and Authorization

Bearer token, constant-time comparison, never logged. `401` for bad
authentication, `403` for insufficient permission. Public: `/health`,
`/version`, `/ready`.

Permissions: `read`, `tools:list`, `scan:passive`, `scan:active`,
`scan:intrusive`, `process:read`, `process:terminate`, `findings:read`,
`engagements:manage`, `admin`. Five roles ship: viewer, scanner, tester,
operator, admin.

## Engagement Scope

Fails closed at every step. Validated: hostname, wildcard domain, IPv4, IPv6,
CIDR, URL, host:port, port, protocol, validity window, risk level.

Five defects were found by a security review of the first implementation and
fixed in `56d7009`:

1. **Scope escape.** `*.example.com` matched `evil-example.com` — the suffix
   test had no dot boundary, so the prefix check saw `evil` and accepted it as
   a single label. Registering a lookalike domain put an attacker in scope.
2. **Fail-open with no engagement.** `validate_target(t, None)` returned
   allowed, so any caller that failed to load an engagement got a full pass.
3. **Fail-open on an empty allow-list.** An empty list skipped the membership
   check entirely, authorizing everything.
4. **SSRF via DNS.** Only literal IPs were checked, so a permitted hostname
   resolving to `169.254.169.254` or RFC1918 space passed. Now every resolved
   address is checked, which closes DNS rebinding; unresolvable names are
   denied rather than assumed safe.
5. **Incomplete IPv6 classification.** Only loopback was checked, so
   `::ffff:169.254.169.254` reached the metadata service in IPv6 notation.

Reserved space still requires explicit authorization, but an IP or CIDR entry
counts — otherwise internal engagements would be unusable. A wildcard hostname
never counts.

## Policy Engine

```python
@dataclass(frozen=True)
class ExecutionPolicy:
    decision: PolicyDecision
    reason: str
    required_permission: Permission | None = None
    requires_approval: bool = False
    policy_code: str | None = None
```

Evaluated in order: authentication → permission for the risk level → engagement
active → target in scope → dangerous-tool approval → destructive requires admin.
Every decision, allow or deny, is audited. The AI layer cannot reach it.

## Execution Security

- Argument arrays, `shell=False`, verified by a test that greps every non-test
  module for `shell=True`.
- Isolated workspace per execution under
  `DATA_DIR/engagements/<eng>/executions/<exec>/`.
- **Process-tree termination.** The old path killed only the direct child. A
  test spawns a parent that forks a child and asserts the grandchild stops
  growing its output file after the timeout — it caught a real bug in the first
  Windows implementation, where `proc.terminate()` succeeding meant the tree
  sweep was skipped, orphaning the grandchild.
- Graceful signal, then forced kill after a grace period.
- stdout and stderr to separate files: no pipe-buffer deadlock, and the raw
  output becomes an artifact.
- Output caps, cancellation, lock-guarded bounded registry, explicit state
  machine that raises on illegal transitions.

## Tool Registry Changes

`ToolSpec` gains `category` (inferred) and `maturity` (asserted). 24 tools are
declared stable; a test rejects any declared-stable name that is not actually
registered — the first draft declared eight tools that did not exist.

Removed: `docker`, `kubectl`, `aws_cli`, `gcloud`, `az`, `adb`, `snyk`,
`shodan_cli`, `strace`, `sliver`.

Added as fixed actions: `aws_get_caller_identity`, `aws_list_s3_buckets`,
`aws_get_bucket_acl`, `aws_list_iam_users`, `gcloud_list_projects`,
`gcloud_list_instances`, `az_account_show`, `az_list_resource_groups`,
`kubectl_get_namespaces`, `kubectl_get_pods`, `kubectl_get_nodes`,
`docker_list_containers`, `docker_inspect_container`, `docker_list_images`,
`adb_list_devices`, `adb_list_packages`, `snyk_test`, `shodan_host_lookup`,
`strace_binary`.

`sliver` (C2) was removed rather than rewritten: enumerating C2 operations
would be adding offensive capability, which was out of scope.

## MCP Changes

Tools are generated from the registry and filtered by profile, so there is no
hand-maintained MCP file to drift. Nine profiles; the default exposes **7 tools
instead of 172**.

Seven resources added: `nexhunter://tools`, `/tools/stable`, `/tools/available`,
`/profiles`, `/executions`, `/findings`, `/system/status`. Plus `--profile`,
`--list-profiles`, and execution visibility tools.

Profiles are a usability and blast-radius control, not a security control: the
policy engine authorizes every execution regardless of which profile surfaced
the tool.

## API Changes

Added: `GET /version`, `/ready`, `/api/tools` (filterable), `/api/tools/{name}`,
`/api/tools/status`, `/api/mcp/profiles`, `/api/executions`,
`/api/executions/{id}`, `/{id}/output`, `/{id}/artifacts`, and
`POST /{id}/terminate`.

Changed: `POST /api/command` no longer accepts `cmd`. Errors carry a stable
`code`.

## Finding Model Changes

**Not implemented.** Findings still use the pre-existing engine model. The
normalized `Finding` dataclass, SHA-256 fingerprints, deduplication, and SARIF
export remain open.

## Autonomous Assessment

Added after the initial eight phases, at the owner's request: the autonomous
execution and real-time adaptation flow, built so the AI drives the loop and
never the operating system.

`agents/profiler.py` accumulates evidence-based knowledge about a target, each
observation carrying its source tool, observed facts kept separate from
inferences. `workflows/orchestrator.py` runs an adaptive loop: a deterministic
planner picks the next tools from the current profile, they run through
`ExecutionService`, results fold back into the profile, and the plan is
recomputed. Detecting WordPress pulls in a WordPress scan; an open 443 pulls in
a TLS check.

The autonomy is bounded three ways the AI cannot lift: every step goes through
the `SecurityGate` (so it cannot leave the engagement scope), a risk ceiling
keeps it to passive and active tools while surfacing intrusive and destructive
ones for human approval, and a step budget stops it running forever. A higher
ceiling requested is clamped, not granted. This is the line the brief draws:
credential attacks, brute force, and exploitation must never run automatically.

This also migrated workflow execution onto `ExecutionService`, so autonomous
runs get real execution records, isolated workspaces, and tree termination that
the old workflow-agent path lacked.

Interfaces: `POST /api/autonomous`, `GET /api/autonomous[/<id>]`, and the MCP
tools `autonomous_assess` / `autonomous_status`. Walkthrough in
`docs/how-it-works.md`. Verified end to end against a live server: a run
planned dns -> httpx -> nuclei -> testssl from observations, withheld an
intrusive tool for approval, and completed inside the step budget.

## Testing Results

```
$ pytest -q
140 passed, 5 warnings in 19.68s
```

14 suites: authentication, authorization, engagement scope, policy engine,
redaction, audit, enforcement, execution layer, execution service,
no-passthrough regressions, MCP profiles, MCP registration, CLI/doctor,
server command, features.

Notable tests, chosen because they would have caught the original defects:

| Test | Guards |
|---|---|
| `test_no_builder_splits_a_parameter_into_argv` | The `["aws"] + cmd.split()` class |
| `test_shell_metacharacters_stay_inert` | Injection payloads stay one argument |
| `test_no_shell_true_anywhere_in_execution_paths` | Greps every non-test module |
| `test_wildcard_does_not_match_sibling_domain` | The `evil-example.com` escape |
| `test_dns_rebinding_to_metadata_blocked` | Hostname resolving to metadata |
| `test_ipv4_mapped_ipv6_metadata_blocked` | `::ffff:169.254.169.254` |
| `test_empty_allowlist_fails_closed` | Empty allow-list authorizing everything |
| `test_runner_timeout_kills_children` | Orphaned grandchildren |
| `test_registry_concurrent_access` | 8 threads × 50 records |
| `test_stable_tools_are_declared_not_guessed` | Phantom stability claims |

## Coverage Results

```
$ pytest --cov=nexhunter --cov-report=term-missing
TOTAL    3452 stmts   1270 miss   63%
```

| Module | Coverage |
|---|---:|
| `security/authentication.py` | 100% |
| `security/enforcement.py` | 100% |
| `execution/models.py` | 100% |
| `security/authorization.py` | 97% |
| `security/audit.py` | 96% |
| `execution/registry.py` | 95% |
| `security/policy.py` | 94% |
| `workflows/security_workflows.py` | 92% |
| `api/mcp_profiles.py` | 89% |
| `security/engagement.py` | 88% |
| `security/redaction.py` | 87% |
| `cli/doctor.py` | 86% |
| `execution/service.py` | 83% |
| `core/availability.py` | 83% |
| `execution/workspace.py` | 82% |
| `execution/runner.py` | 76% |
| `core/tools.py` | 63% |
| `api/mcp.py` | 60% |
| `cli/client.py` | 43% |
| `api/server.py` | 33% |
| `agents/*` | 24–47% |
| `core/engine.py` | 24% |

**63% is below the 80% target.** The security-critical paths are covered; the
shortfall is legacy agent, engine, and interface code that predates this work.
Raising it means writing tests for those modules, which is listed as next-phase
work rather than reported as done.

## CI Results

`.github/workflows/ci.yml` added: pytest across Python 3.10–3.13 on Linux and
Windows, plus ruff, mypy, bandit, pip-audit, package build, and a dedicated
security-regression job. No offensive binaries are installed and nothing is
scanned.

**Not yet observed green** — the workflow has not run on a remote at the time
of writing. The same commands pass locally. `ruff format --check`, `mypy`, and
`pip-audit` are marked advisory so a formatting sweep or an unfixable upstream
advisory does not block the pipeline.

## Breaking Changes

1. **`POST /api/command` no longer accepts `cmd`.** Use
   `{"tool": ..., "params": {...}}`. Intentional; this was the main hole.
2. **Ten tools renamed or removed.** `aws_cli` → `aws_get_caller_identity` and
   friends; `sliver` removed.
3. **Authentication required** when `NEXHUNTER_API_TOKEN` is set.
4. **MCP exposes 7 tools by default, not 172.** Pass `--profile nexhunter-full`
   for the old behavior.
5. **Python 3.10+** (was 3.8+); modern typing syntax is used throughout.
6. **`nexhunter` console script** replaces `python nexhunter.py`.

## Migration Guide

```bash
pip install -e ".[mcp]"
nexhunter doctor
```

Raw command callers:

```diff
- {"cmd": "nmap -sV example.com"}
+ {"tool": "nmap_scan", "params": {"target": "example.com"}}
```

Cloud callers:

```diff
- {"tool": "aws_cli", "params": {"command": "s3api list-buckets"}}
+ {"tool": "aws_list_s3_buckets", "params": {}}
```

MCP config: add `"--profile", "nexhunter-core"` (or a task-specific profile) and
move the token into the client's `env` block.

Enabling enforcement:

```bash
nexhunter engagement validate scope.json
export NEXHUNTER_ENFORCE=true NEXHUNTER_ENGAGEMENT=$PWD/scope.json
nexhunter doctor          # fails loudly if this is misconfigured
```

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `NEXHUNTER_API_TOKEN` | *(unset)* | Bearer token; unset means no authentication |
| `NEXHUNTER_ENFORCE` | `true` | Require engagement scope; false disables it |
| `NEXHUNTER_ENGAGEMENT` | *(unset)* | Path to engagement JSON |
| `NEXHUNTER_DEFAULT_ROLE` | `operator` | Role granted to an authenticated caller |
| `NEXHUNTER_BIND_HOST` | `127.0.0.1` | Listen address |
| `NEXHUNTER_EXTERNAL_BIND_ALLOWED` | `false` | Permit non-loopback binding |
| `NEXHUNTER_DATA_DIR` | `./nexhunter_data` | Workspace and artifact root |
| `NEXHUNTER_AUDIT_LOG_PATH` | *(data dir)* | Audit log location |
| `NEXHUNTER_MCP_PROFILE` | `nexhunter-core` | Default MCP profile |
| `NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED` | `false` | Feature flag |
| `NEXHUNTER_INTRUSIVE_TOOLS_ENABLED` | `false` | Feature flag |

## Installation and Usage

```bash
pip install -e ".[mcp]"
nexhunter doctor
nexhunter registry check
python -m nexhunter.api.server --port 8888
python -m nexhunter.api.mcp --server http://127.0.0.1:8888 --profile nexhunter-recon
```

Verified: `pip install -e .` succeeds and `nexhunter doctor` runs from outside
the repository.

## Remaining Risks

1. **Enforcement can still be disabled** with `NEXHUNTER_ENFORCE=false`, and
   nothing prevents that reaching production except discipline. `doctor`
   reports the posture.
2. **Coverage is 63%, not 80%.** Legacy modules are thin.
3. **Not a sandbox.** Tools run with the server process's privileges.
4. **TOCTOU on DNS.** Scope is checked at request time; the tool resolves again
   later. The window is small but real.
5. **Redaction is pattern-based** and may miss unusual credential formats.
6. **Short-flag redaction is a hand-maintained per-binary map.** A credential
   tool not on that list could leak a `-p` value into an audit record.
7. **Workflows bypass the new execution layer**, so workflow runs get no
   per-phase records or workspaces.
8. **Categories are keyword-inferred.** 64 tools land in `other` and appear
   only in the full profile.
9. **CI is unverified on a remote.**
10. **`datetime.utcnow()` deprecation** across several modules.

## Recommended Next Phase

1. Typed parameter schemas (`hostname`, `cidr`, `url`, `port`, `file`) with
   per-parameter `secret` markers, which also retires the short-flag map.
2. (done) Autonomous runs execute through `ExecutionService`; the legacy standalone workflow-agent path remains for non-autonomous flows.
3. Finding normalization: SHA-256 fingerprints, deduplication, SARIF export.
4. Raise coverage on `api/server.py`, `core/engine.py`, and `agents/`.
5. Run CI on a remote and fix what it surfaces.
6. (done) Evidence-based target profiler and autonomous orchestration.
