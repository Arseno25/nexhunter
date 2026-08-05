# NexHunter Project Structure

Professional security assessment platform - clean, organized folder hierarchy.

## Directory Layout

```
nexhunter/
├── agents/                    # AI agents for security workflows
│   ├── base.py               # Base agent class
│   ├── __init__.py           # Agent registry
│   ├── browser.py            # Browser agent
│   ├── decision.py           # Decision engine agent
│   ├── flows.py              # Bug bounty & CTF workflows
│   ├── intel.py              # CVE & exploit intelligence
│   ├── ops.py                # Operations agents (monitoring, recovery)
│   └── enhanced.py           # Enhanced security agents (OSINT, threat intel)
│
├── api/                       # HTTP API server & web UI
│   ├── server.py             # Main server with endpoints
│   ├── mcp_ui.py             # Modern web control panel
│   ├── mcp.py                # MCP bridge
│   ├── visual.py             # Visual components (cards, progress)
│   └── security_features.py  # Advanced security features
│
├── cli/                       # Command-line interface
│   ├── client.py             # Professional CLI client
│   └── __init__.py           # CLI module init
│
├── core/                      # Core engine & tools
│   ├── config.py             # Configuration (cache, timeouts, limits)
│   ├── tools.py              # 24 security tools registry
│   ├── engine.py             # Assessment engine (caching, execution)
│   └── __init__.py           # Core module init
│
├── workflows/                 # Comprehensive assessment workflows
│   ├── security_workflows.py  # 9 workflow types (bug bounty, pentest, etc)
│   ├── workflow_agents.py     # 6 workflow agents
│   └── __init__.py            # Workflows module init
│
├── tests/                     # Testing suite
│   ├── test_features.py       # Comprehensive feature tests (12/12 passing)
│   └── __init__.py            # Tests module init
│
├── docs/                      # Documentation
│   ├── README.md              # Main documentation
│   └── UI_GUIDE.md            # UI & CLI usage guide
│
├── config/                    # Configuration files
│   └── nexhunter-mcp.json     # MCP configuration
│
├── __init__.py                # Package init
├── requirements.txt           # Python dependencies
└── __pycache__/               # Bytecode cache (auto-generated)
```

## Component Count

- **Agents**: 13 core + 5 enhanced = 18 total
- **Workflows**: 9 comprehensive types
- **API Endpoints**: 30+ REST endpoints
- **Tools**: 24 security assessment tools
- **CLI Commands**: 15+ commands
- **Tests**: 12 passing (100%)

## File Organization

| Folder | Purpose | Files |
|--------|---------|-------|
| `agents/` | AI agents & workflows | 8 |
| `api/` | Server & UI | 5 |
| `cli/` | Command-line interface | 2 |
| `core/` | Engine & tools | 4 |
| `workflows/` | Assessment procedures | 3 |
| `tests/` | Test suite | 2 |
| `docs/` | Documentation | 2 |
| `config/` | Configuration | 1 |
| Root | Package files | 3 |

**Total**: 30 Python files + config

## Quick Navigation

### For Security Assessment
→ See `workflows/security_workflows.py` for 9 assessment types

### For API Usage
→ See `docs/UI_GUIDE.md` for REST endpoints and usage

### For CLI Usage
→ Run `python nexhunter.py --help` or see `cli/client.py`

### For Tool Configuration
→ Edit `core/config.py` (cache, timeouts, limits)

### For Adding Tools
→ Update `core/tools.py` with new ToolSpec

### For Adding Agents
→ Subclass `agents/base.py` Agent class

## Architecture Overview

```
User Interface Layer
├── Web UI (api/mcp_ui.py)
├── CLI (cli/client.py)
└── MCP Bridge (api/mcp.py)

Agent Layer
├── Core Agents (13)
├── Enhanced Agents (5)
└── Workflow Agents (6)

Workflow Layer
├── 9 Assessment Workflows
└── Phase Management

Execution Layer
├── Assessment Engine (core/engine.py)
├── Tool Execution (core/tools.py)
└── Result Processing (api/visual.py)

Foundation Layer
├── Configuration (core/config.py)
├── Type System (dataclasses)
└── Caching & Dedup
```

## Status

- ✓ Clean folder organization
- ✓ Separate concerns (agents/api/cli/core/workflows)
- ✓ Comprehensive documentation
- ✓ Full test coverage (12/12 passing)
- ✓ Production-ready code

---

**Last Updated**: 2026-08-05
**Version**: 3.1.0
**Status**: Complete & Organized
