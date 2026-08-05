# MCP Setup

NexHunter exposes its tool registry over MCP (Model Context Protocol) through a
FastMCP bridge. The bridge is a thin proxy: every call goes to the same REST
API, the same policy engine, and the same audit log that a human operator hits.
Nothing is reachable over MCP that would be refused over REST.

> Only use NexHunter against systems you own or are explicitly authorized to assess.

## How it fits together

```
AI client  ──stdio/MCP──►  nexhunter.api.mcp  ──HTTP──►  nexhunter.api.server
(Claude, Cursor, …)         (profile filter)              (policy, scope, audit,
                                                           execution, workspaces)
```

The bridge decides **what a client is shown**. The server decides **what is
allowed to run**. Those are separate on purpose: hiding a tool is a usability
choice, not a security control.

## 1. Start the server

```bash
python -m nexhunter.api.server --port 8888
```

Binds to `127.0.0.1` by default. See [../deployment.md](../deployment.md) before
exposing it anywhere else.

## 2. Pick a profile

Listing all ~170 registered tools to every client makes for a large
initialization payload, a large token cost on every session, and a model
choosing between near-identical tools with no basis to pick. A profile narrows
that to one job.

```bash
python -m nexhunter.api.mcp --list-profiles
```

| Profile | Exposes |
|---|---|
| `nexhunter-core` | **Default.** Status, findings, executions, and passive stable checks only |
| `nexhunter-recon` | Host discovery, DNS, subdomain enumeration, service identification |
| `nexhunter-web` | Web scanning: content discovery, templates, tech identification, TLS |
| `nexhunter-api` | API surface testing: schema and parameter discovery, GraphQL |
| `nexhunter-code` | Static analysis, secret scanning, dependency review |
| `nexhunter-cloud` | Read-only cloud posture review |
| `nexhunter-container` | Container and Kubernetes image and configuration review |
| `nexhunter-forensics` | Offline artifact and binary analysis |
| `nexhunter-full` | Every non-destructive tool. Large payload; prefer a focused profile |

No profile lists a destructive tool. Reaching one takes explicit, separately
configured setup plus an approval record.

## 3. Configure your client

Per-client instructions:

- [Claude Desktop](claude-desktop.md)
- [Claude Code](claude-code.md)
- [Cursor](cursor.md)
- [VS Code](vscode.md)
- [Roo Code](roo-code.md)
- [OpenCode](opencode.md)

All of them take the same shape:

```json
{
  "mcpServers": {
    "nexhunter": {
      "command": "python",
      "args": [
        "-m", "nexhunter.api.mcp",
        "--server", "http://127.0.0.1:8888",
        "--profile", "nexhunter-core"
      ],
      "env": {
        "NEXHUNTER_API_TOKEN": "your-token-here"
      }
    }
  }
}
```

Use an absolute interpreter path if the client does not inherit your shell
environment (most do not):

- Linux/macOS: `/usr/bin/python3` or `/path/to/.venv/bin/python`
- Windows: `C:\Python313\python.exe` or `.venv\Scripts\python.exe`

## Authentication

If the server has `NEXHUNTER_API_TOKEN` set, the bridge must send the same
token. Pass it through the client's `env` block (above) or with `--token`.
Prefer `env`: a token on the command line is visible in the process list.

Without a matching token every tool call comes back `AUTH_REQUIRED`.

## Resources

Alongside tools, the bridge publishes read-only resources a client can pull
without spending a tool call:

| URI | Contents |
|---|---|
| `nexhunter://tools` | Full registry with category, risk, maturity, availability |
| `nexhunter://tools/stable` | Only tools with parsers, fixtures, and tests |
| `nexhunter://tools/available` | Tools whose binary is installed on this host |
| `nexhunter://profiles` | Profiles and their tool counts |
| `nexhunter://executions` | Recent executions with status and policy decision |
| `nexhunter://findings` | Findings recorded so far |
| `nexhunter://system/status` | Server health and tool availability |

## What the model cannot do

- **Run an arbitrary command.** There is no command parameter anywhere in the
  registry, and no execution path uses a shell. Model output is a tool name
  plus typed parameters; it is never a command line.
- **Choose its own scope.** Targets are checked against the engagement, and
  denied entries beat allowed ones.
- **Override policy.** The policy engine evaluates every call server-side. A
  model asking more confidently does not change the answer.
- **Reach a destructive tool by asking.** Those are disabled by default and
  require an admin permission and an approval record.

## Troubleshooting

**No tools appear.** The client cannot start the bridge. Run the exact command
from your config by hand; a wrong interpreter path is the usual cause.

**Everything returns `AUTH_REQUIRED`.** The bridge's token does not match the
server's. Check `NEXHUNTER_API_TOKEN` on both sides.

**`server unreachable`.** The server is not running, or is on another port.
Confirm with `curl http://127.0.0.1:8888/health`.

**A tool returns `BINARY_NOT_FOUND`.** The tool is registered but not installed.
NexHunter never installs binaries for you. Check
`curl http://127.0.0.1:8888/api/tools/status` for what is present.

**Too many tools in the client.** Switch to a narrower `--profile`.
