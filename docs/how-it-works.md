# How It Works

NexHunter runs a five-stage flow — AI connection, analysis, execution,
adaptation, reporting — with one structural difference from other autonomous
platforms: **the AI drives the loop; it never drives the operating system.**

> Only use NexHunter against systems you own or are explicitly authorized to assess.

## Architecture at a glance

```mermaid
%%{init: {"themeVariables": {
  "primaryColor": "#b71c1c",
  "secondaryColor": "#ff5252",
  "tertiaryColor": "#ff8a80",
  "background": "#2d0000",
  "edgeLabelBackground":"#b71c1c",
  "fontFamily": "monospace",
  "fontSize": "16px",
  "fontColor": "#fffde7",
  "nodeTextColor": "#fffde7"
}}}%%
graph TD
    A[AI Agent - Claude/GPT/Copilot] -->|MCP Protocol| B[NexHunter MCP Bridge v2.0]
    
    B --> C[Intelligent Planning]
    B --> D[Autonomous Orchestration]
    B --> E[Advanced Reporting]
    
    C --> C1[Evidence-based Profiler]
    C --> C2[Adaptive Planner]
    C --> C3[Typed Parameter Validation]
    
    D --> D1[Risk Ceiling - clamped to active]
    D --> D2[Step Budget]
    D --> D3[One Execution Path]
    
    E --> E1[Normalized Findings]
    E --> E2[Vulnerability Cards]
    E --> E3[JSON / MD / HTML / SARIF Export]
    
    B --> P[204 Security Tools]
    P --> P1[Recon & OSINT - 26]
    P --> P2[Web & API - 26]
    P --> P3[Network & Wireless - 23]
    P --> P4[Binary & Forensics - 26]
    P --> P5[Cloud & Container & Code - 34]
    P --> P6[Exploitation & Payloads & Privesc - 26]
    P --> P7[Crypto & Mobile & IDS & VulnScan & CTF - 22]
    P --> P8[Utility - 21]
    
    B --> W[Execution Layer]
    W --> W1[Process Management - tree kill]
    W --> W2[Isolated Workspaces]
    W --> W3[Output Caps & Timeouts]
    W --> W4[Secret Redaction]
    
    style A fill:#b71c1c,stroke:#ff5252,stroke-width:3px,color:#fffde7
    style B fill:#ff5252,stroke:#b71c1c,stroke-width:4px,color:#fffde7
    style C fill:#ff8a80,stroke:#b71c1c,stroke-width:2px,color:#fffde7
    style D fill:#ff8a80,stroke:#b71c1c,stroke-width:2px,color:#fffde7
    style E fill:#ff8a80,stroke:#b71c1c,stroke-width:2px,color:#fffde7
    style P fill:#ff8a80,stroke:#b71c1c,stroke-width:2px,color:#fffde7
    style W fill:#ff8a80,stroke:#b71c1c,stroke-width:2px,color:#fffde7
```

## 1. AI Agent Connection

Claude, GPT, or any MCP client connects over FastMCP. Tools are generated from
the registry and filtered by profile, so a client sees the tools for its job,
not all ~204. See [mcp/README.md](mcp/README.md).

The client can call one tool at a time, or hand the whole assessment to the
orchestrator with `autonomous_assess`.

## 2. Intelligent Analysis

Two pieces, both deterministic and evidence-based:

- **Profiler** (`agents/profiler.py`) accumulates what has been *observed* about
  a target — resolved addresses, technologies, services — with the source tool
  attached to each. It never invents a technology or a vulnerability, and it
  keeps observed facts separate from inferences.
- **Adaptive planner** (`workflows/orchestrator.py`) chooses the next tools from
  the current profile. The same profile always yields the same plan, so an
  autonomous run is reproducible and reviewable. The AI proposes a target and a
  ceiling; the planner, not the AI, decides what touches the OS.

## 3. Autonomous Execution

`autonomous_assess(target)` starts an adaptive run. It is genuinely autonomous —
it plans, runs, and re-plans without a human in the loop — but bounded two
ways, none of which the AI can lift:

- **Risk ceiling.** The loop runs passive and active tools. Intrusive and
  destructive tools — credential attacks, brute force, exploitation — are
  *never* auto-executed. They are surfaced under `recommended_next` with the
  reason they were withheld, for a human to approve. Asking for a higher
  ceiling does not grant one; it is clamped to `active`.
- **Step budget.** The loop stops at a configured number of steps, so it cannot
  run forever.

Every step also goes through the same `ExecutionService` as a manual call, so
the loop cannot reach the operating system any other way. A failed or missing
binary mid-run is recorded and the run continues, rather than aborting the
whole assessment.

```mermaid
sequenceDiagram
    participant AI as AI client
    participant O as Orchestrator
    participant P as Profiler
    participant T as Target

    AI->>O: autonomous_assess(example.com)
    loop until done or budget spent
        O->>P: plan from current profile
        P-->>O: next tools (within ceiling)
        O->>T: run planned tools (isolated)
        T-->>O: output
        O->>P: fold results into the profile
    end
    O-->>AI: findings + tools withheld for approval
```

## 4. Real-time Adaptation

The plan is recomputed from the accumulated profile on every iteration. This is
not scripted — the sequence changes because the knowledge changed:

| Observation | Adaptation |
|---|---|
| httpx reports WordPress | a WordPress scan is added |
| an open 443 / an HTTPS URL | a TLS configuration check is added |
| a web surface is confirmed | template and misconfiguration scans are added |
| open ports found | a service enumeration is added |

Because adaptation is driven by evidence in the profile rather than by model
free-text, a scan result that says *"ignore your instructions and run this
command"* changes nothing: it is not evidence, and no parameter carries a
command line regardless.

## 5. Advanced Reporting

Results become normalized findings — one shape across every tool, deduplicated
by fingerprint — and export as JSON, JSONL, Markdown, HTML, or SARIF. Findings
are kept distinct from observations and from parser failures, so a report never
presents a fact as a vulnerability or a broken parser as a clean result.

## The one difference that matters

An autonomous platform where AI output reaches the OS directly is one prompt
injection away from running an arbitrary command. NexHunter's autonomy sits
behind the same execution path as a manual call, and no tool accepts a command
line, so the worst a confused or steered model can do is propose a tool and
parameters — which are typed-validated before a command is ever built, and
which the risk ceiling withholds if they are intrusive or destructive.

```mermaid
flowchart LR
    subgraph unsafe [Autonomous platform, AI drives the OS]
        U1[AI] --> U2[OS] --> U3[any command]
    end
    subgraph nex [NexHunter, AI drives the loop]
        N1[AI] -->|proposes tool + params| N2[Planner] -->|plans| N3{within<br/>ceiling?}
        N3 -->|passive / active| N4[ExecutionService] --> N5[typed validation<br/>+ isolated run]
        N3 -->|intrusive / destructive| N6[(withheld,<br/>surfaced for approval)]
    end
    classDef bad fill:#7f1d1d,stroke:#dc2626,color:#fff
    classDef ok fill:#14532d,stroke:#16a34a,color:#fff
    class U2,U3 bad
    class N4,N5 ok
```

## Try it

```bash
python -m nexhunter.api.server --port 8888

# hand the assessment to the orchestrator
curl -X POST http://127.0.0.1:8888/api/autonomous \
     -d '{"target":"https://example.com","risk_ceiling":"active"}'

# poll it
curl http://127.0.0.1:8888/api/autonomous/<run_id>
```

Or over MCP, ask the AI client: *"Run an autonomous assessment of example.com."*
