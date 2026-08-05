# NexHunter Upgrade Report

**Baseline:** `b19f979` · **Date:** 2026-08-05
**Diff (initial upgrade):** 69 files changed, 10,014 insertions, 199 deletions

> This report is a point-in-time snapshot of the security upgrade. It is kept
> verbatim as history; later work is tracked in the addendum at the bottom.
> Current numbers (tools, tests, profiles) live in the [README](../README.md).

## Addendum (2026-08-06)

Since this report was written:

- **Browser engine** (`agents/browser.py`): Selenium-backed page analysis,
  screenshots, network capture, crawl, and form discovery, with a stdlib
  fallback when Selenium/Chrome is absent. Exposed as `/api/browser/*`.
- **Visual engine** (`api/visual.py`): HexStrike-style severity cards, live
  dashboard, progress bars; ANSI with ASCII degradation and `NO_COLOR`.
- **REST rewrite**: the server moved from Werkzeug to Flask; one HTTP server
  now hosts REST + MCP + the visual endpoints.
- **Registry grew** to 257 tools (29 stable / 206 beta / 22 experimental) with
  16 MCP profiles; `nexhunter-full` (default) exposes 255.
- **Freeform execution** (`shell_command`, `python_script`): HexStrike-style
  raw command execution restored as two registry tools — intrusive, recorded,
  uncacheable, withheld from autonomous runs, and surfaced by every profile
  (they serve any engagement; opt out per profile).
- **Zero-noise toolchain**: 263 ruff errors → 0, 70 mypy errors → 0, the suite
  runs at **327 passing tests with no warnings** (previously 304 + a collection
  error + a warning). `test_selector.py` collection was broken (bad package
  import) and hid one failing test that is now fixed; the CI `mypy` step was
  pointing at a path that never resolved.
- The old report's "remaining risks" 6 and 7 (`CI unverified`, `utcnow`
  deprecation) are now the only unremediated items; risk 4 (hand-maintained
  short-flag map) was deliberately retained.

## Executive Summary

NexHunter was a capable tool orchestrator with a modular layout and no
execution safety model. Any caller reaching the port could run any registered
tool against any target, and `/api/command` accepted a raw operating-system
command string. The README claimed 100% test coverage; the actual figure was
under 10%.

The first upgrade pass added a heavy security layer: authentication,
permissions, engagement scope, a deterministic policy engine, audit logging,
plus secret redaction, isolated execution, and MCP profiles. A later
architecture review removed the auth/scope/audit/policy machinery entirely: it
added per-request ceremony without blocking the operator, and the operator is
the only caller. What remains is the part that protects the host and the
operator's data, not the part that second-guesses the operator:

- typed parameter validation and no arbitrary-command surfaces
- secret redaction everywhere records are stored or displayed
- isolated per-execution workspaces, tree-termination, output caps
- one execution path (`ExecutionService`) for REST, MCP, and CLI
- a bounded autonomy loop whose risk ceiling is clamped to `active`
- MCP profiles (7 tools by default instead of 172)

Three arbitrary-command surfaces were removed, and two secret leaks were
found and fixed while testing.

**Not finished:** finding normalization was completed after this report's
first draft; legacy agent and engine code still has thinner test coverage
than the execution and findings layers.

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
| 3 | No typed parameter validation | Critical | Fixed |
| 4 | No secret redaction; credentials reached records and logs | High | Fixed |
| 5 | Timeouts killed only the direct child, orphaning scanners | High | Fixed |
| 6 | No workspace isolation; artifacts shared one directory | High | Fixed |
| 7 | Unsynchronized shared process state under a threaded server | Medium | Fixed |
| 8 | False "100% test coverage" claim | Medium | Fixed |
| 9 | `requirements.txt` only; no installable package | Medium | Fixed |

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

## Design Decisions

**Adopted:** MCP client onboarding, tool availability and version detection,
process visibility, execution termination, tool categories, system status,
rich CLI status output, MCP profile support, evidence-based target profiling,
adaptive planning.

**Rejected:** a monolithic server and MCP module, `shell=True`, an
arbitrary-command API, a generic file-manager API, unrestricted
`additional_args`, string-based command construction, generic cloud/Docker/
Kubernetes passthrough, and marketing claims without evidence.

**Removed (deliberately, in the final pass):** authentication, authorization,
engagement scope, the policy engine, and audit logging. They existed because
the first brief treated the operator as untrusted. The operator is the only
caller, so they became ceremony: per-request token checks, scope files, and
denial records no one read. The retained model is input safety, containment,
and bounded autonomy — controls that protect the operator's machine and data
rather than gate the operator.

## New Architecture

```
security/     redaction only
execution/    models (state machine) · workspace · runner · registry · service
core/         tools · params (typed validation) · risk · availability
workflows/    orchestrator (adaptive loop, clamped risk ceiling)
api/          mcp_profiles · server · mcp
cli/          doctor · registry · profiles
```

Every caller enters through `ExecutionService`. Diagrams in
[architecture.md](architecture.md).

## Input Safety (replaces the policy engine)

- Every parameter declares a type, a default, and a validation rule
  (`core/params.py`). A value that is not a valid target, port, or enum is
  refused before a command is ever built.
- No parameter carries a command line; no builder splits a string into argv;
  no execution path uses a shell — except the single sanctioned
  `shell_command` builder contract (a `ShellCommand` string), gated as
  intrusive. Regression tests fail if anything else is reintroduced.
- Secret-shaped parameters are redacted by name (with per-binary short-flag
  resolution, so `-p` is a password to hydra and a port list to nmap) in
  records, logs, and responses.

## Execution Security

- Argument arrays by default; `shell=True` never appears in the codebase —
  shell mode exists only as the builder's `ShellCommand` contract, derived at
  the runner's single spawn site, verified by a test that greps every
  non-test module.
- Isolated workspace per execution under
  `DATA_DIR/executions/<exec>/`.
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
registered.

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
instead of 172**. Seven resources (`nexhunter://tools`, `/tools/stable`,
`/tools/available`, `/profiles`, `/executions`, `/findings`,
`/system/status`) plus `--profile` and `--list-profiles`.

## Finding Model Changes

Completed: normalized `Finding` dataclass, SHA-256 fingerprints over the
identifying fields, deduplication with merge (severity never downgraded),
parser failures recorded as their own category, and JSON / JSONL / Markdown /
HTML / SARIF export. Evidence is redacted before storage.

## Autonomous Assessment

`agents/profiler.py` accumulates evidence-based knowledge about a target, each
observation carrying its source tool, observed facts kept separate from
inferences. `workflows/orchestrator.py` runs an adaptive loop: a deterministic
planner picks the next tools from the current profile, they run through
`ExecutionService`, results fold back into the profile, and the plan is
recomputed. Detecting WordPress pulls in a WordPress scan; an open 443 pulls in
a TLS check.

The autonomy is bounded two ways the AI cannot lift: a risk ceiling keeps it to
passive and active tools while surfacing intrusive and destructive ones for
human approval, and a step budget stops it running forever. A higher ceiling
requested is clamped, not granted. Credential attacks, brute force, and
exploitation never run automatically.

Interfaces: `POST /api/autonomous`, `GET /api/autonomous[/<id>]`, and the MCP
tools `autonomous_assess` / `autonomous_status`. Walkthrough in
`docs/how-it-works.md`.

## Exploit Kit (agents/exploit_kit)

Replaced the monolithic `agents/exploit_ai.py` (1,327 lines, one SyntaxError,
duplicated helpers) with a modular package of eight independent agents,
auto-registered through the same `agents/` discovery — no server or MCP changes
were needed. Functionally equivalent to their exploit agents but with
original names, structure, and payload data (ATM: Amati–Tiru–Modifikasi, not
1:1 copy).

| Module | Agent | Replaces | Scope |
|---|---|---|---|
| `forge.py` | `switchblade` | `payload_gen` | 11 attack types × complexity × tech context |
| `forge.py` | `ghost_wright` | `payload_advanced` | evasion 4 level + size/quote constraints |
| `cve.py` | `cve_smith` | `exploit_cve` | NVD fetch → classify → Python exploit builder |
| `salvo.py` | `fireworks` | `attack_suite` | multi-category suite via real agent orchestration |
| `impact.py` | `rangefinder` | `payload_tester` | all 7 HTTP methods, data/headers injection |
| `plan.py` | `blitzplan` | `attack_chain` | objective-based attack chains |
| `plan.py` | `warroom` | `attack_chains` | web/network/cloud chain templates |
| `autopilot.py` | `autopilot` | `autonomous_exploit` | optimizer-driven real engine execution |

Design:

- `core.py` is the single source of payload data: 11 attack categories,
  per-technology contexts, shell payloads (bash/nc/python3/php/powershell/
  socat), DB error markers for SQLi detection, encoding/obfuscation helpers.
- `salvo`, `blitzplan`, and `autopilot` call other agents / the engine instead
  of re-implementing their logic, so payload knowledge lives in exactly one
  place.
- `autopilot` runs tools only through `get_tool_spec` availability checks and
  the same `RiskLevel` ceiling used by the orchestrator: intrusive tools are
  skipped unless `authorized=True`, anything above the ceiling is surfaced as
  `recommended_next` for human approval. Exploitation never runs unattended.
- `rangefinder` detects reflected payloads, SQL error signatures, SSTI
  stacktraces, time-based responses, LFI/XXE/SSRF/open-redirect markers.
- Original bug fixes from the old module carried over: `%{0}` PowerShell
  templates escaped for `.format()`, missing `target_url` parameter in exploit
  builders, wrong context constant names.

Tests: `tests/test_exploit_kit.py` — 59 tests covering registration (new
agents present, old names removed), every attack category, every evasion level,
constraint application, all HTTP methods against a local echo server, exploit
code generation per kind, chain plans, and autopilot risk-ceiling behavior.

```
$ pytest -q tests/test_exploit_kit.py
59 passed
```

## Testing Results

```
$ pytest -q
143 passed in 18.23s
```

14 suites: execution layer, execution service, findings, autonomous
orchestration, no-passthrough regressions, MCP profiles, MCP registration,
CLI/doctor, config, server command, redaction, params, features, availability.

Notable tests:

| Test | Guards |
|---|---|
| `test_no_builder_splits_a_parameter_into_argv` | The `["aws"] + cmd.split()` class |
| `test_shell_metacharacters_rejected_by_typed_validation` | Injection payloads stay one argument |
| `test_only_sanctioned_builders_emit_shell_commands` | Exactly one builder returns a ShellCommand |
| `test_no_shell_true_anywhere_in_execution_paths` | Greps every non-test module |
| `test_runner_timeout_kills_children` | Orphaned grandchildren |
| `test_registry_concurrent_access` | 8 threads × 50 records |
| `test_serialization_has_no_secrets` | No auth/scope/audit settings survive |
| `test_evidence_is_redacted` | Credentials cannot reach stored evidence |
| `test_autonomous_never_exceeds_risk_ceiling` | Autonomy cannot escalate itself |

## Remaining Risks

1. **Not a sandbox.** Tools run with the server process's privileges.
2. **No callers are authenticated.** Bind to loopback, or put something
   authenticated in front of the port. `doctor` fails loudly on non-loopback
   binding without `NEXHUNTER_EXTERNAL_BIND_ALLOWED`.
3. **Redaction is pattern-based** and may miss unusual credential formats.
4. **Short-flag redaction is a hand-maintained per-binary map.**
5. **Categories are keyword-inferred.** 64 tools land in `other` and appear
   only in the full profile.
6. **CI is unverified on a remote.**
7. **`datetime.utcnow()` deprecation** across several modules.
8. **Freeform tools are a raw execution surface.** `shell_command` and
   `python_script` run exactly what a caller types (metacharacters live for
   `shell_command`). The containment is procedural — intrusive gate, no
   autonomous runs, operator presence required — not a sandbox.

## Recommended Next Phase

1. Run CI on a remote and fix what it surfaces.
2. Raise coverage on `api/server.py`, `core/engine.py`, and `agents/`.
3. Verify `pip-audit` / `mypy` advisories.
4. Replace `datetime.utcnow()` usage with timezone-aware UTC.

## Addendum (2026-08-06) — Freeform execution (HexStrike-style)

Restores raw command execution as a *registered, gated capability* rather than
a raw endpoint:

- `shell_command` and `python_script` registered in `core/tools.py`. There is
  **no shell flag anywhere**: a builder either returns an argv list (default)
  or a `ShellCommand` (a str subclass) when the whole payload must run through
  the OS shell. The ProcessRunner is the only spawn site and derives the mode
  from that type (`isinstance(cmd, ShellCommand)`); the service layers pass
  the builder output through untouched.
- New `ParamType.TEXT` (`core/params.py`): free-form text that allows newlines
  but still rejects null bytes; used only by the two freeform tools.
- Both tools are `intrusive`, uncacheable, 120s timeout, recorded on the
  tracked path, and withheld from autonomous runs by the existing risk ceiling
  (orchestrator clamps to `active`).
- **Every MCP profile surfaces both tools** — like the workflow tools, since
  they serve any engagement. `Profile.include_freeform_tools` (default True)
  lets a profile opt out; the dedicated `nexhunter-freeform` profile was
  removed as redundant.
- Regression updates: `ALLOWED_TEXT_PARAMS` lists `shell_command.command` with
  a reason; `test_no_shell_true_anywhere_in_execution_paths` stays unchanged
  (no literal `shell=True` exists in the codebase);
  `test_only_sanctioned_builders_emit_shell_commands` proves exactly one
  builder returns a `ShellCommand`.
- New suite `tests/test_freeform_tools.py` (10 tests); total 327 passing.
- Earlier addendum entry "Registry grew" reflects 257 tools / 16 profiles /
  full = 255.
