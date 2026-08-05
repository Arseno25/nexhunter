# MCP Setup

NexHunter exposes its tool registry over MCP (Model Context Protocol) through a
FastMCP bridge. The bridge is a thin proxy: every call goes to the same REST
API and the same execution path that a human operator hits. Nothing is
reachable over MCP that would be refused over REST.

> Only use NexHunter against systems you own or are explicitly authorized to assess.

## How it fits together

```
AI client  ──stdio/MCP──►  nexhunter.api.mcp  ──HTTP──►  nexhunter.api.server
(Claude, Cursor, …)         (profile filter)              (validation, execution,
                                                           workspaces, findings)
```

The bridge decides **what a client is shown**. The server decides **what is
valid**. Those are separate on purpose: hiding a tool is a usability choice,
not a security control.

## 1. Start the server

```bash
python -m nexhunter.api.server --port 8888
```

Binds to `127.0.0.1` by default. See the production configuration section of
[security-model.md](../security-model.md) before exposing it anywhere else.

## 2. Pick a profile

Listing all ~257 registered tools to every client makes for a large
initialization payload, a large token cost on every session, and a model
choosing between near-identical tools with no basis to pick. A profile narrows
that to one job.

```bash
python -m nexhunter.api.mcp --list-profiles
```

| Profile | Exposes |
|---|---|
| `nexhunter-core` | Status, findings, executions, and passive stable checks only |
| `nexhunter-recon` | Host discovery, DNS, subdomain enumeration, service identification |
| `nexhunter-web` | Web security: content discovery, injection testing, templates, TLS — incl. sqlmap/ffuf/nikto |
| `nexhunter-api` | API surface testing: schema discovery, parameter discovery (arjun), GraphQL |
| `nexhunter-code` | Static analysis, secret scanning, dependency review |
| `nexhunter-cloud` | Read-only cloud posture review |
| `nexhunter-container` | Container and Kubernetes image and configuration review |
| `nexhunter-forensics` | Offline artifact, steganography, and binary analysis |
| `nexhunter-osint` | OSINT: username and email footprinting, maltego/spiderfoot, CVE lookup |
| `nexhunter-wireless` | Wireless reconnaissance and assessment (destructive withheld) |
| `nexhunter-privesc` | Local privilege escalation discovery scripts |
| `nexhunter-payloads` | Payload generation and C2 integration (never auto-executed) |
| `nexhunter-vulnscan` | Vulnerability scanners and network IDS tooling |
| `nexhunter-mobile` | APK inspection, decompilation, runtime exploration |
| `nexhunter-ctf` | One-stop CTF profile: Web Exploitation, Cryptography, Reverse Engineering & Pwn, Forensics, OSINT |
| `nexhunter-full` | **Default (no `--profile`).** Every non-destructive tool. Large payload; prefer a focused profile when you know the job |

Every profile also surfaces the two freeform tools — `execute_command` (raw
shell command strings, free-form style) and `execute_python_script` (Python snippets).
Both are intrusive, recorded, and withheld from autonomous runs; a profile can
opt out with `include_freeform_tools=False`.

No profile lists a destructive tool. Reaching one takes explicit, separately
configured setup.

Without `--profile`, the bridge defaults to `nexhunter-full` — every
non-destructive tool. If your client shows too many tools, narrow it with
`--profile nexhunter-recon` or similar.

## 3. Configure your client

Every supported client (Claude Desktop, Claude Code, Cursor, VS Code, Roo
Code, OpenCode) uses the same configuration shape — only the interpreter path
differs. The JSON below works in all of them:

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

Use an absolute interpreter path if the client does not inherit your shell
environment (most do not):

- Linux/macOS: `/usr/bin/python3` or `/path/to/.venv/bin/python`
- Windows: `C:\Python313\python.exe` or `.venv\Scripts\python.exe`

## Resources

Alongside tools, the bridge publishes read-only resources a client can pull
without spending a tool call:

| URI | Contents |
|---|---|
| `nexhunter://tools` | Full registry with category, risk, maturity, availability |
| `nexhunter://tools/stable` | Only tools with parsers, fixtures, and tests |
| `nexhunter://tools/available` | Tools whose binary is installed on this host |
| `nexhunter://profiles` | Profiles and their tool counts |
| `nexhunter://executions` | Recent executions with status |
| `nexhunter://findings` | Findings recorded so far |
| `nexhunter://system/status` | Server health and tool availability |

## What the model cannot do

- **Run an arbitrary command.** There is no command parameter anywhere in the
  registry except the sanctioned `execute_command` — intrusive, withheld from
  autonomous runs, and off every default profile. Model output is a tool name
  plus typed parameters; it is never a command line.
- **Send invalid parameters.** Values are type-checked server-side; a value
  that is not a valid target, port, or enum is refused before a command is
  ever built.
- **Escalate an autonomous run.** The orchestrator's risk ceiling is clamped
  to `active`; a model asking for more does not get it.
- **Reach a destructive tool by asking.** Those are disabled by default and
  require a feature flag plus a human decision.

## Troubleshooting

**No tools appear.** The client cannot start the bridge. Run the exact command
from your config by hand; a wrong interpreter path is the usual cause.

**`server unreachable`.** The server is not running, or is on another port.
Confirm with `curl http://127.0.0.1:8888/health`.

**A tool returns `BINARY_NOT_FOUND`.** The tool is registered but not installed.
NexHunter never installs binaries for you. Check
`curl http://127.0.0.1:8888/api/tools/status` for what is present.

**Too many tools in the client.** Switch to a narrower `--profile`.
