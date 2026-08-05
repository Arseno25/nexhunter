# NexHunter

<div align="center">
  <img src="assets/nexhunter.png" alt="NexHunter" width="300">

  <strong>Tool-Driven AI Security Orchestration</strong>

  <p>Safe orchestration of security tools for <em>authorized</em> assessments.</p>

![Version](https://img.shields.io/badge/version-2.0.0-blue) ![Python](https://img.shields.io/badge/python-3.10%2B-green) ![Tests](https://img.shields.io/badge/tests-143%20passing-green)
</div>

---

> [!WARNING]
> **Only use NexHunter against systems you own or are explicitly authorized to assess.**

---

## What it is

NexHunter orchestrates external security tools through one execution path. It
does not implement scanners — it validates a request, runs it safely in an
isolated workspace, and records what happened.

The distinguishing property: **an AI client is a caller like any other.** It can
propose a tool and parameters. It cannot propose a command line, and the
autonomous loop cannot escalate its own risk ceiling.

## How it works

```mermaid
flowchart LR
    A[REST] --> E[ExecutionService]
    B[MCP / AI client] --> E
    C[CLI] --> E
    D[Autonomous loop] --> E
    E --> R[Registry - 252 tools]
    E --> G[validate + build argv]
    E --> S[run isolated + record]
    style E fill:#0e7490,stroke:#06b6d4,stroke-width:3px,color:#f8fafc
```

1. **One execution path** — every caller (REST, MCP, CLI, autonomous loop) walks
   the same code: lookup → typed validation → build argv → isolated run → record.
2. **The registry** — 252 `ToolSpec`s with typed params, risk, category,
   maturity; profiles slice it per client.
3. **The loop** — autonomous assessment: profiler evidence → planner → bounded
   by a clamped risk ceiling and a step budget.
4. **The ledger** — observations, inferences, and findings kept separate;
   deduplicated, exported as JSON/MD/HTML/SARIF.
5. **The boundary** — the AI can propose tools and parameters, never a command
   line; no path to the OS except `ExecutionService`.

Full walkthrough with a call trace, sequence diagram, and the can/cannot table:
[docs/how-it-works.md](docs/how-it-works.md).

## Quick start

```bash
git clone https://github.com/Arseno25/nexhunter.git
cd nexhunter
pip install -e ".[mcp]"

nexhunter doctor          # check this installation can actually run
```

Then start the server and, optionally, the MCP bridge:

```bash
python -m nexhunter.api.server --port 8888
python -m nexhunter.api.mcp --server http://127.0.0.1:8888 --profile nexhunter-recon
```

## MCP setup

Add to your AI client's config (Claude Desktop, Claude Code, Cursor, VS Code,
Roo Code, OpenCode — see [docs/mcp/](docs/mcp/)):

```json
{
  "mcpServers": {
    "nexhunter": {
      "command": "python",
      "args": [
        "-m", "nexhunter.api.mcp",
        "--server", "http://127.0.0.1:8888",
        "--profile", "nexhunter-core"
      ]
    }
  }
}
```

### Profiles

Listing ~252 tools to every client makes for a large payload, a large token
cost, and a model choosing blindly between near-identical tools. A profile
narrows that to one job.

| Profile | Tools | Purpose |
|---|---:|---|
| `nexhunter-core` | 12 | Status, findings, executions, passive stable checks only |
| `nexhunter-recon` | 24 | Host discovery, DNS, subdomains, service identification |
| `nexhunter-web` | 37 | Content discovery, injection testing, template scanning, TLS, browser crawl (incl. sqlmap/ffuf/nikto) |
| `nexhunter-api` | 7 | Schema and parameter discovery (arjun), JWT, GraphQL |
| `nexhunter-code` | 16 | Static analysis, secret scanning, dependency review |
| `nexhunter-cloud` | 8 | Read-only cloud posture |
| `nexhunter-container` | 14 | Container and Kubernetes review |
| `nexhunter-forensics` | 28 | Offline artifact, steganography, and binary analysis |
| `nexhunter-osint` | 10 | OSINT: usernames, emails, footprinting, CVE lookup |
| `nexhunter-wireless` | 7 | Wireless recon and assessment (destructive withheld) |
| `nexhunter-privesc` | 7 | Local privilege escalation discovery |
| `nexhunter-payloads` | 10 | Payload generation, C2 integration (never auto-executed) |
| `nexhunter-vulnscan` | 10 | Vulnerability scanners and IDS tooling |
| `nexhunter-mobile` | 6 | APK inspection, decompilation, runtime exploration |
| `nexhunter-ctf` | 91 | All CTF domains: web, crypto, RE/pwn, forensics, OSINT |
| `nexhunter-full` | 250 | **Default (no `--profile`).** Everything non-destructive. Large payload |

```bash
nexhunter profiles                          # list them
nexhunter profiles --name nexhunter-web     # see what one exposes
```

No profile lists a destructive tool. Without `--profile`, the bridge exposes
`nexhunter-full` (250 tools); pass a profile to narrow the payload. Profiles
are a usability control, not a security control — every execution goes through
the same typed validation regardless of which profile surfaced the tool.

## Autonomous assessment

Hand a whole assessment to the orchestrator and it plans, runs, and re-plans as
results arrive — the autonomous, adaptive flow, but bounded so the AI drives the
loop, never the operating system.

```bash
curl -X POST http://127.0.0.1:8888/api/autonomous \
     -d '{"target":"https://example.com","risk_ceiling":"active"}'
```

Or over MCP: *"Run an autonomous assessment of example.com."*

Plan-first over MCP (the AI proposes, the registry and ceiling filter):

```bash
curl -X POST http://127.0.0.1:8888/api/plan \
     -d '{"target":"https://example.com","risk_ceiling":"active",
          "steps":[{"tool":"nmap_scan","params":{"target":"example.com"}}]}'
```

`propose_plan` validates the AI's steps *without executing anything* and
returns `approved`, `withheld`, and `invalid` lists; the approved list is then
passed back via `autonomous_assess(steps=...)`, where every step is
re-validated a second time before it runs. The AI writes the plan; the registry
and the ceiling filter it.

Two bounds the AI cannot lift:

- **Risk ceiling.** It runs passive and active tools. Intrusive and destructive
  tools are never auto-run — they are surfaced with a reason for human
  approval. A higher ceiling requested is clamped to `active`, not granted.
- **Step budget.** It stops after a set number of steps.

Every step also goes through the same `ExecutionService` as a manual call, so
the loop cannot reach the operating system any other way.

Full walkthrough with diagrams: [docs/how-it-works.md](docs/how-it-works.md).

## Security model

Enforced and covered by tests:

- **No arbitrary command execution.** No tool takes a command parameter, no
  builder splits a string into argv, no path uses a shell. Shell metacharacters
  stay inert as single literal arguments.
- **Typed validation.** Every parameter declares a type, a default, and a
  validation rule; a value that is not a valid target, port, or enum is refused
  before a command is ever built.
- **Bounded autonomy.** The orchestrator's ceiling is clamped to `active`;
  intrusive and destructive tools are withheld for human approval, and
  destructive tools additionally require a feature flag.
- **Contained execution.** Isolated workspace per run, timeouts that kill the
  whole process tree, output caps, no path traversal or symlink escape.
- **Secrets redacted** from parameters, commands, logs, and output.
- **One execution path.** REST, MCP, and CLI cannot diverge.

Full detail, and an explicit list of what is *not* guaranteed, in
[docs/security-model.md](docs/security-model.md).

## CLI

```bash
nexhunter doctor                              # environment health check
nexhunter registry list --category recon      # browse the registry
nexhunter registry check                      # which binaries are installed
nexhunter registry info nmap_scan             # describe one tool
nexhunter profiles                            # MCP profiles
```

`doctor` reports what is true about your environment and never changes it:

```
NexHunter Doctor

Core
  [OK] Python 3.13.7
  [OK] Data directory writable
  [OK] Server binds to loopback (127.0.0.1)
  [OK] Process execution works

Security
  [OK] Raw command execution disabled (registry tools only)
  [OK] No execution path uses a shell
  [OK] Destructive tools disabled

Stable tools (8/24 installed)
  [OK] nmap_scan (nmap 7.80)
  [OK] curl_headers (curl 8.12.1)
  [MISSING] 16 other stable tools not installed

Registry availability (23/252 tools on PATH)
  [OK] web: 5/37 available
  [MISSING] wireless: 0/9 available
```

NexHunter never installs binaries for you.

## API

```bash
curl -X POST http://127.0.0.1:8888/api/command \
     -d '{"tool": "nmap_scan", "params": {"target": "example.com", "ports": "80,443"}}'
```

| Endpoint | Purpose |
|---|---|
| `GET /health` `/ready` `/version` | Server status |
| `GET /api/tools` | Registry, filterable by category, risk, maturity, availability |
| `GET /api/tools/{name}` | One tool's metadata |
| `GET /api/tools/status` | What is installed |
| `POST /api/command` | Run a registered tool |
| `GET /api/executions` | Execution history with status |
| `GET /api/executions/{id}/output` | Captured output, redacted |
| `GET /api/executions/{id}/artifacts` | Artifacts in that execution's workspace |
| `POST /api/executions/{id}/terminate` | Stop a running execution and its children |
| `POST /api/autonomous` | Start an adaptive autonomous assessment |
| `GET /api/autonomous[/{id}]` | Run status and result |
| `GET /api/findings` | Findings |
| `GET /api/mcp/profiles` | Profile definitions |

The server binds to `127.0.0.1` by default and `doctor` fails loudly on any
other binding unless `NEXHUNTER_EXTERNAL_BIND_ALLOWED` is set.

## Tool maturity

Maturity is asserted per tool, never guessed.

| Level | Meaning | Count |
|---|---:|---:|
| **stable** | Command builder, availability check, tests | 24 |
| **beta** | Registered and validated, less exercised | 180 |

Cloud, container, and orchestration access is exposed as fixed read-only
actions (`aws_get_caller_identity`, `kubectl_get_pods`,
`docker_list_containers`), never as a CLI passthrough.

## Configuration

```bash
NEXHUNTER_ENVIRONMENT=development            # production refuses destructive tools
NEXHUNTER_BIND_HOST=127.0.0.1
NEXHUNTER_BIND_PORT=8888
NEXHUNTER_EXTERNAL_BIND_ALLOWED=false
NEXHUNTER_DATA_DIR=./nexhunter_data
NEXHUNTER_MCP_PROFILE=nexhunter-full
NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED=false
NEXHUNTER_INTRUSIVE_TOOLS_ENABLED=false
```

See [.env.example](.env.example).

## Testing

```bash
pytest                                                    # 143 tests
pytest --cov=nexhunter --cov-report=term-missing          # coverage
```

Coverage is measured, not claimed. The execution and findings layers are the
best covered; legacy agent and engine code is thinner.

## Limitations

- Not a sandbox. Tools run with the server process's privileges.
- The server does not authenticate callers; bind to loopback or put something
  authenticated in front of the port.
- Redaction is pattern-based and may miss unusual credential formats.

## Roadmap

- Migrate legacy workflow definitions onto `ExecutionService`
- Raise coverage on `api/server.py`, `core/engine.py`, and `agents/`
- Replace deprecated `datetime.utcnow()` usage

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Layers, execution flow, state machine, diagrams |
| [docs/security-model.md](docs/security-model.md) | Threat model, guarantees, non-guarantees |
| [docs/how-it-works.md](docs/how-it-works.md) | One execution path, call trace, the loop, and the can/cannot boundary |
| [docs/mcp/](docs/mcp/) | MCP setup per client |

## Contributing

Adding a tool means adding a `ToolSpec` with a command builder that takes
discrete values — never a command string. See
[docs/architecture.md](docs/architecture.md). The regression suite in
`tests/test_no_passthrough.py` will reject a passthrough.

---

<div align="center">
<strong>NexHunter v2.0.0</strong> — Tool-Driven AI Security Orchestration<br>
<a href="https://github.com/Arseno25/nexhunter">GitHub</a>
</div>
