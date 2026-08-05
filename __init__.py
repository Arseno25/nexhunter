"""NexHunter - AI-driven security assessment engine (MCP + HTTP API).

Architecture base: tool registry -> MCP/HTTP layer for AI agents.
Original code with real implementations: structured output parsing,
smart result caching, parallel execution, tech-aware tool selection,
correlated findings, and 13 AI agents (technology, decision, optimizer,
rate_limit, cve, exploit, recovery, performance, degradation,
correlator, bugbounty, ctf, browser).

Layout:
    core/    tools.py (registry + parsers), engine.py (orchestration)
    agents/  13 AI agents, each a real implementation
    api/     server.py (HTTP API), mcp.py (MCP bridge)
    cli/     client.py (command-line client)

Run:
    pip install -r requirements.txt
    python -m nexhunter.api.server --port 8888
    python -m nexhunter.api.mcp --server http://127.0.0.1:8888
    python nexhunter.py health
"""

__version__ = "3.0.0"
