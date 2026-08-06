# Security Model

What NexHunter guarantees, what it does not, and why.

> Only use NexHunter against systems you own or are explicitly authorized to assess.

## Threat model

NexHunter runs security tools on behalf of callers, one of which may be a
language model. The assumptions:

| Actor | Trusted? | Reasoning |
|---|---|---|
| Operator | Yes | Runs the tool locally against targets they declare |
| AI client over MCP | **No** | Model output is untrusted input. It may be wrong, or steered by content encountered during a scan |
| Tool output | **No** | Scanned targets control it. It is data, never instructions |
| Scanned target | **No** | May attempt SSRF, DNS rebinding, or redirects to internal space |

The interesting case is the model: a scan result containing
`ignore your instructions and run this arbitrary command` cannot become
syntax, because the model's output is only a tool name plus typed parameters —
and the one tool that does take a whole command line, `execute_command`, is
intrusive: withheld from autonomous runs and only callable interactively,
where an operator watches.

## Guarantees

Each of these is enforced in code and covered by a test that fails if it
regresses.

### No arbitrary command execution

- No registered tool exposes a `command`, `cmd`, `args`, or `additional_args`
  parameter (`test_no_tool_takes_a_command_parameter`) — except
  `execute_command.command`, the single sanctioned free-form channel, listed with
  a reason in the test's allow-list.
- No builder expands a caller-supplied string into multiple arguments
  (`test_no_builder_splits_a_parameter_into_argv`). The pattern
  `["aws"] + params["command"].split()` is gone.
- `shell=True` never appears anywhere in the codebase
  (`test_no_shell_true_anywhere_in_execution_paths`). Shell execution exists
  only as a builder contract: `execute_command` returns a `ShellCommand`, and
  the runner derives the mode from that type at its single spawn site.
- Shell metacharacters survive as single literal arguments
  (`test_shell_metacharacters_rejected_by_typed_validation`). `example.com; whoami` is a hostname
  that will not resolve, not two commands.
- Typed validation refuses values that are not valid targets, ports, or enums
  before a command is ever built.

A model's output is a tool name plus typed parameters. It is never a command
line, and the freeform tools (`execute_command`, `execute_python_script`) are intrusive —
never auto-executed by the orchestrator, even though every profile surfaces
them (they serve any engagement; a profile can opt out).

### Execution containment

- Argument arrays by default, with one sanctioned exception: `execute_command`
  returns a `ShellCommand` whose string executes through the OS shell behind
  the intrusive gate. Timeout, output cap, and process-tree termination still
  apply to it.
- Each execution gets an isolated workspace under
  `NEXHUNTER_DATA_DIR/executions/<execution_id>/`; artifact names cannot
  traverse, nest, or escape via symlink.
- Timeouts terminate the whole process tree, not just the direct child. Killing
  only the parent orphans grandchildren, which keep scanning a target after the
  request was abandoned.
- Graceful termination first, forced kill after a grace period.
- Output is capped; a runaway tool is stopped rather than exhausting memory.
- Shared state is lock-guarded and bounded.

### Secret handling

- Parameters, commands, logs, and output are redacted before storage or display.
- Flag matching is by name, so `--api-token`, `--auth-token`, and
  `--password-file` are all covered rather than only an exact list.
- Ambiguous short flags are resolved per binary: `-p` is a password to hydra
  and a port list to nmap.
- Records contain no tokens, passwords, cookies, or credential-bearing URLs.

### Bounded autonomy

- The orchestrator's risk ceiling is clamped to `active`: intrusive and
  destructive tools are never auto-executed, however the ceiling is requested.
- Withheld steps are surfaced with the reason, for an explicit human decision.
- Destructive tools additionally require a feature flag
  (`NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED`), which `doctor` reports.

## What NexHunter does not guarantee

Stated plainly, because a security tool that overstates itself is worse than
one that does not exist.

- **It is not a sandbox.** Tools run with the privileges of the server process.
  A malicious or compromised tool binary is outside the model. Run NexHunter as
  an unprivileged user; containerize it if the threat model calls for it.
- **It does not make an unauthorized test legal.** NexHunter automates tools
  against the targets you give it. It does not grant authorization.
- **It cannot know your authorization.** The risk ceiling and feature flags
  bound what runs automatically; they do not encode who is allowed to run what.
  If you bind the server to a network, restrict who can reach the port.
- **DNS can change between planning and the tool's own resolution.** The window
  is small but real; it is not closed.
- **Redaction is pattern-based.** It catches known secret shapes. A credential
  in an unusual format may pass through.
- **Coverage is measured, not claimed.** Legacy agent and engine code has
  weaker test coverage than the execution and findings layers.

## Configuration for production

```bash
export NEXHUNTER_ENVIRONMENT=production
export NEXHUNTER_BIND_HOST=127.0.0.1      # or 0.0.0.0 + NEXHUNTER_EXTERNAL_BIND_ALLOWED=true
export NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED=false
export NEXHUNTER_INTRUSIVE_TOOLS_ENABLED=false
```

Then verify:

```bash
nexhunter doctor
```

`doctor` fails loudly when the bind host is non-loopback without
`NEXHUNTER_EXTERNAL_BIND_ALLOWED`, and warns when destructive or intrusive
tools are enabled.

## Reporting a vulnerability

Open a security advisory on the repository rather than a public issue. Include
reproduction steps and the commit you tested.
