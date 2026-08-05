# Workflows

A workflow is a phased sequence of tool executions. Each phase runs through the
same execution path as a single call: a workflow cannot reach a target or a
risk level that a direct call could not.

> Only use NexHunter against systems you own or are explicitly authorized to assess.

## How a workflow relates to the execution path

```mermaid
flowchart TB
    W[Workflow definition<br/>phases · required tools · max risk] --> P1
    subgraph phases [Phases run in order]
        P1[Phase 1] --> P2[Phase 2] --> P3[Phase 3]
    end
    P1 -.-> SVC
    P2 -.-> SVC
    P3 -.-> SVC
    SVC{ExecutionService<br/>typed validation<br/>+ containment}
    SVC -->|failed| SKIP[Phase records the failure<br/>and continues]
    SVC -->|ok| RUN[Execute]

    classDef deny fill:#7f1d1d,stroke:#dc2626,color:#fff
    class SVC deny
```

A workflow is a *plan*, not an authorization. Every step still runs through the
single execution path, so a failed step mid-workflow stops that step rather
than granting the rest a pass.

## Passive reconnaissance

The safest workflow: nothing touches the target directly beyond DNS and public
records.

```mermaid
flowchart LR
    A[Domain] --> B[whois]
    A --> C[DNS records]
    A --> D[Subdomain enumeration<br/>passive sources]
    D --> E[HTTP probe<br/>status · title · tech]
    B & C & E --> F[(Findings)]

    classDef passive fill:#14532d,stroke:#16a34a,color:#fff
    class B,C,D,E passive
```

Risk level: `passive`.

## Web assessment

```mermaid
flowchart TB
    A[Target URL] --> B[HTTP probe]
    B --> C{Responsive?}
    C -->|no| STOP[Stop and report]
    C -->|yes| D[Technology identification]
    D --> E[TLS configuration]
    D --> F[Content discovery]
    D --> G[Template scanning]
    F --> H{Interesting paths?}
    H -->|yes| G
    E & G --> I[(Findings)]

    classDef passive fill:#14532d,stroke:#16a34a,color:#fff
    classDef active fill:#78350f,stroke:#d97706,color:#fff
    class B,D,E passive
    class F,G active
```

Risk level: `active` at the discovery and scanning phases.

## Code and dependency review

Operates on a local checkout. No traffic leaves the host, so there is no target
scope to check — but the workspace rules still apply.

```mermaid
flowchart LR
    A[Source tree] --> B[Static analysis]
    A --> C[Secret scanning]
    A --> D[Dependency audit]
    B & C & D --> E[(Findings)]

    classDef passive fill:#14532d,stroke:#16a34a,color:#fff
    class B,C,D passive
```

Risk level: `passive`.

## Cloud posture review

Every registered cloud action is read-only. There is no CLI passthrough, so a
workflow cannot reach a mutating operation.

```mermaid
flowchart LR
    A[Credentials in the environment] --> B[Identity check]
    B --> C[Storage inventory]
    B --> D[IAM inventory]
    C --> E[Bucket ACLs]
    D & E --> F[(Findings)]

    classDef passive fill:#14532d,stroke:#16a34a,color:#fff
    class B,C,D,E passive
```

Risk level: `passive`. Uses `aws_get_caller_identity`, `aws_list_s3_buckets`,
`aws_get_bucket_acl`, `aws_list_iam_users` and their GCP and Azure equivalents.

## Container review

```mermaid
flowchart LR
    A[Cluster or host] --> B[List namespaces]
    A --> C[List containers]
    B --> D[List pods]
    C --> E[Inspect container]
    D & E --> F[Image vulnerability scan]
    F --> G[(Findings)]

    classDef passive fill:#14532d,stroke:#16a34a,color:#fff
    class B,C,D,E,F passive
```

## Writing a workflow

A workflow declares what it needs up front so it can be validated before
anything runs:

```python
@dataclass(frozen=True)
class WorkflowDefinition:
    name: str
    description: str
    phases: tuple[WorkflowPhase, ...]
    maximum_risk_level: RiskLevel
    required_tools: tuple[str, ...]
```

Rules:

- A phase names registry tools. It never constructs a command.
- `maximum_risk_level` is a ceiling, not a grant: the autonomy loop's ceiling
  still applies.
- A missing tool is reported, not worked around. NexHunter does not install
  binaries.
- A failed step is recorded as a phase result. Workflows do not retry past a
  failure that the tools themselves report.

## Progress reporting

```json
{
  "workflow_id": "...",
  "name": "web-standard",
  "status": "running",
  "current_phase": "technology_detection",
  "progress": 40,
  "executions": [],
  "findings": [],
  "errors": []
}
```

## Current state

The workflow definitions in `workflows/` predate the execution layer and still
drive tools through the older engine path rather than `ExecutionService`.
Migrating them is on the roadmap; until then, per-phase execution records and
workspaces are not produced for workflow runs. Direct tool calls through
`/api/command` and MCP, and autonomous runs through the orchestrator, do get
the full treatment.
