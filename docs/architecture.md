# Architecture

NexHunter is a policy-driven orchestration layer over external security tools.
It does not implement scanners; it decides whether a scan may run, runs it
safely, and records what happened.

> Only use NexHunter against systems you own or are explicitly authorized to assess.

## The one rule

Every execution — from the REST API, from an AI client over MCP, from the CLI —
goes through the same gate. There is no second path.

```mermaid
flowchart LR
    subgraph clients [Callers]
        REST[REST API]
        MCP[MCP / AI client]
        CLI[CLI]
    end

    SVC[ExecutionService<br/>the only execution path]

    REST --> SVC
    MCP --> SVC
    CLI --> SVC

    SVC --> GATE{SecurityGate}
    GATE -->|denied| AUDIT[(Audit log)]
    GATE -->|allowed| RUN[ProcessRunner]
    RUN --> AUDIT
    RUN --> WS[(Per-execution<br/>workspace)]

    classDef deny fill:#7f1d1d,stroke:#dc2626,color:#fff
    classDef allow fill:#14532d,stroke:#16a34a,color:#fff
    class GATE deny
    class RUN allow
```

An AI client is a caller like any other. It can propose a tool and parameters;
it cannot propose a command, widen its own scope, or overrule the policy engine.

## Layers

```mermaid
flowchart TB
    subgraph interface [Interface]
        A1[api/server.py<br/>REST]
        A2[api/mcp.py<br/>FastMCP bridge]
        A3[cli/client.py]
    end

    subgraph service [Service]
        B1[execution/service.py]
    end

    subgraph policy [Security]
        C1[security/enforcement.py<br/>SecurityGate]
        C2[security/authentication.py]
        C3[security/authorization.py]
        C4[security/engagement.py<br/>scope]
        C5[security/policy.py<br/>decisions]
        C6[security/redaction.py]
        C7[security/audit.py]
    end

    subgraph exec [Execution]
        D1[execution/runner.py]
        D2[execution/workspace.py]
        D3[execution/registry.py]
        D4[execution/models.py]
    end

    subgraph registry [Registry]
        E1[core/tools.py<br/>ToolSpec]
        E2[core/availability.py]
        E3[api/mcp_profiles.py]
    end

    interface --> service
    service --> policy
    service --> exec
    service --> registry
    C1 --> C2 & C3 & C5
    C5 --> C4
    C1 --> C7
    C7 --> C6
```

| Layer | Responsibility | Must not |
|---|---|---|
| Interface | Parse requests, shape responses | Build commands, spawn processes, decide policy |
| Service | Sequence validate → authorize → run → record | Contain tool-specific logic |
| Security | Decide who may run what, against which targets | Be bypassable by any caller |
| Execution | Run a process safely and contain its output | Decide whether it should run |
| Registry | Describe tools and their parameters | Execute anything |

## What happens on one execution

```mermaid
sequenceDiagram
    participant C as Caller
    participant S as ExecutionService
    participant G as SecurityGate
    participant P as PolicyEngine
    participant R as ProcessRunner
    participant A as Audit log

    C->>S: tool name + parameters
    S->>S: look up ToolSpec (unknown tool → reject)
    S->>S: validate parameters
    Note over S: record created: QUEUED → VALIDATING

    S->>G: authorize(tool, target, risk)
    G->>G: authenticate bearer token
    G->>P: evaluate policy
    P->>P: permission for this risk level?
    P->>P: engagement active?
    P->>P: target in scope? (denied beats allowed)
    P->>P: dangerous tool needs approval?
    P-->>G: PolicyDecision
    G->>A: write decision (allowed or denied)
    G-->>S: GateResult

    alt denied
        S-->>C: BLOCKED + policy code
    else allowed
        Note over S: AUTHORIZED
        S->>S: build argv from ToolSpec
        S->>S: create isolated workspace
        Note over S: RUNNING
        S->>R: run(argv, timeout, workspace)
        R->>R: spawn in its own process group
        R->>R: enforce timeout and output cap
        R-->>S: exit code, stdout, stderr
        Note over S: COMPLETED / FAILED / TIMED_OUT / TERMINATED
        S-->>C: result with secrets redacted
    end
```

## Execution states

A record moves through an explicit state machine. Illegal transitions raise
rather than silently corrupting the record, so a blocked execution can never
appear to have run.

```mermaid
stateDiagram-v2
    [*] --> queued
    queued --> validating
    validating --> authorized: policy allows
    validating --> blocked: policy denies
    authorized --> running
    authorized --> blocked
    running --> completed: exit 0
    running --> failed: non-zero exit
    running --> timed_out: deadline passed
    running --> terminated: cancelled or output cap

    completed --> [*]
    failed --> [*]
    timed_out --> [*]
    terminated --> [*]
    blocked --> [*]
```

## Scope enforcement

Target validation is the part most worth understanding, because it is where an
authorized assessment stops being authorized. It fails closed at every step.

```mermaid
flowchart TD
    T[Target] --> E{Engagement<br/>present?}
    E -->|no| D1[DENY<br/>scope unverifiable]
    E -->|yes| ACT{Engagement<br/>active?}
    ACT -->|no| D2[DENY]
    ACT -->|yes| EMPTY{Allow-list<br/>empty?}
    EMPTY -->|yes| D3[DENY<br/>empty allows nothing]
    EMPTY -->|no| HOST[Reduce URL / host:port<br/>to bare host]

    HOST --> DEN{In denied list?}
    DEN -->|yes| D4[DENY<br/>denied beats allowed]
    DEN -->|no| ALW{In allowed list?}
    ALW -->|no| D5[DENY]
    ALW -->|yes| RES[Resolve every address<br/>the name points at]

    RES -->|resolution fails| D6[DENY]
    RES --> META{Metadata IP?}
    META -->|yes| D7[DENY<br/>always, even if allowed]
    META -->|no| RSV{Reserved / private?}
    RSV -->|no| OK[ALLOW]
    RSV -->|yes| EXP{Named literally, or<br/>covered by an IP/CIDR entry?}
    EXP -->|yes| OK
    EXP -->|no| D8[DENY<br/>a wildcard must not<br/>reach internal space]

    classDef deny fill:#7f1d1d,stroke:#dc2626,color:#fff
    classDef allow fill:#14532d,stroke:#16a34a,color:#fff
    class D1,D2,D3,D4,D5,D6,D7,D8 deny
    class OK allow
```

Resolving the name is what stops DNS rebinding: a host that passes the
name-based check but points at `169.254.169.254` or `10.0.0.5` is still denied.

## Policy decisions

```mermaid
flowchart LR
    R[Risk level] --> P[passive]
    R --> A[active]
    R --> I[intrusive]
    R --> X[destructive]

    P --> P1[authenticated<br/>+ in scope]
    A --> A1[+ scan:active<br/>+ risk allowed by engagement]
    I --> I1[+ scan:intrusive<br/>+ approval record]
    X --> X1[admin permission<br/>+ feature flag<br/>+ approval<br/>disabled by default]

    classDef low fill:#14532d,stroke:#16a34a,color:#fff
    classDef mid fill:#78350f,stroke:#d97706,color:#fff
    classDef high fill:#7f1d1d,stroke:#dc2626,color:#fff
    class P1 low
    class A1 mid
    class I1,X1 high
```

Credential attacks, brute force, payload generation, exploitation, persistence,
data modification, denial of service, wireless deauthentication, and destructive
cloud actions never run automatically. They require an explicit approval record.

## MCP profiles

The bridge decides what a client is *shown*. The server decides what is
*allowed*. Hiding a tool is a usability choice, not a security control.

```mermaid
flowchart LR
    REG[(Tool registry<br/>~170 tools)] --> F{Profile filter<br/>category · risk · maturity}
    F --> C[core · 7]
    F --> RC[recon · 15]
    F --> W[web · 13]
    F --> AP[api · 13]
    F --> CD[code · 10]
    F --> CL[cloud · 8]
    F --> CT[container · 10]
    F --> FR[forensics · 17]
    F --> FU[full · 172]

    C --> CLIENT[AI client]
    CLIENT -.->|every call still| GATE{SecurityGate}

    classDef gate fill:#7f1d1d,stroke:#dc2626,color:#fff
    class GATE gate
```

The default profile exposes 7 tools rather than 172, which cuts initialization
payload and token cost and stops a model choosing blindly between near-identical
tools.

## Artifact containment

```
NEXHUNTER_DATA_DIR/
└── engagements/
    └── <engagement_id>/
        └── executions/
            └── <execution_id>/
                ├── stdout.log
                ├── stderr.log
                └── <tool artifacts>
```

Identifiers and artifact names are validated against a strict pattern, paths are
canonicalized, and symlinks are resolved before the containment check. There is
no general file-manager API: artifacts are reachable only by name, only within
one execution's workspace.

## Deliberate non-goals

- **No autonomy.** NexHunter does not decide to attack anything. A model
  proposes; the policy engine disposes.
- **No arbitrary command execution.** No parameter carries a command line, no
  builder splits a string into argv, no path uses a shell.
- **No binary installation.** Missing tools are reported, never fetched.
- **No offensive capability added.** Tools that only make sense for attack (C2
  frameworks) are not registered.

## Module map

| Path | Contents |
|---|---|
| `security/authentication.py` | Bearer tokens, constant-time comparison |
| `security/authorization.py` | Permissions and roles |
| `security/engagement.py` | Engagement model, target validation, DNS checks |
| `security/policy.py` | Deterministic execution decisions |
| `security/redaction.py` | Secret detection for logs, records, output |
| `security/audit.py` | Structured JSON audit log |
| `security/enforcement.py` | SecurityGate: ties the above together |
| `execution/models.py` | ExecutionRecord and its state machine |
| `execution/workspace.py` | Per-execution isolated directories |
| `execution/runner.py` | Process spawning, tree termination, output caps |
| `execution/registry.py` | Concurrency-safe, bounded record store |
| `execution/service.py` | The single execution path |
| `core/tools.py` | ToolSpec registry and command builders |
| `core/availability.py` | Binary presence and version detection |
| `api/mcp_profiles.py` | Profile definitions and filtering |
| `cli/doctor.py` | Environment health check |

## Related

- [security-model.md](security-model.md) — threat model and guarantees
- [mcp/README.md](mcp/README.md) — MCP setup and client configuration
- [HEXSTRIKE_COMPARISON.md](HEXSTRIKE_COMPARISON.md) — comparison with HexStrike AI
