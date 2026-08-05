"""NexHunter - tool-driven AI security orchestration (MCP + HTTP API).

Architecture: typed tool registry -> one execution path (ExecutionService)
for REST, MCP, and CLI -> isolated workspaces -> normalized findings.

Layout:
    core/       tools.py (registry + parsers), params.py (typed validation),
                risk.py, availability.py, engine.py (legacy orchestration)
    execution/  models (state machine) · workspace · runner · registry · service
    findings/   models (normalization) · store (dedup) · export
    agents/     profiler (evidence-based target knowledge)
    workflows/  orchestrator (bounded adaptive autonomy)
    api/        server.py (HTTP API), mcp.py (MCP bridge), mcp_profiles.py
    cli/        client.py, doctor.py
    security/   redaction.py (secret hygiene)

Run:
    pip install -e ".[mcp]"
    nexhunter doctor
    python -m nexhunter.api.server --port 8888
    python -m nexhunter.api.mcp --server http://127.0.0.1:8888
"""

__version__ = "1.0.0"
