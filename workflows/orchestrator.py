"""Autonomous, adaptive assessment orchestration.

This is the piece that lets an AI client say "assess example.com" and have a
whole sequence run, adapting as results come in — autonomous execution with
real-time adaptation.

  * The loop runs through ExecutionService, the same path a manual call takes.

  * There is a risk ceiling. The loop autonomously runs passive and active
    tools. Anything above the ceiling -- intrusive or destructive: credential
    attacks, brute force, exploitation -- is never auto-executed. It is
    surfaced as a recommendation with the reason it was withheld, for a human
    to approve.

  * There is a step budget, so a loop cannot run forever.

Real-time adaptation is real: the plan is recomputed from the accumulated
profile on every iteration. Detecting WordPress pulls in a WordPress scan;
finding an open TLS port pulls in a TLS check. The AI does not choose what
runs against the OS -- the planner does, from evidence.
"""

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from nexhunter.core import tools as T
from nexhunter.core.risk import RiskLevel
from nexhunter.agents.profiler import Profiler, TargetProfile

_RISK_ORDER = {
    RiskLevel.PASSIVE: 0,
    RiskLevel.ACTIVE: 1,
    RiskLevel.INTRUSIVE: 2,
    RiskLevel.DESTRUCTIVE: 3,
}


class RunStatus(Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass
class PlannedStep:
    """A tool the planner wants to run next, and why."""

    tool: str
    reason: str
    risk_level: str


class AdaptivePlanner:
    """Choose the next tools from what has been observed so far.

    Deterministic on purpose: the same profile yields the same plan, so an
    autonomous run is reproducible and reviewable. The AI can propose a target
    and a ceiling; it does not get to invent the tool list.
    """

    # Seed steps by target type, run before anything is known.
    SEED = {
        "web_application": [
            ("dns_lookup", "resolve the target"),
            ("httpx_probe", "identify HTTP status, title, and technology"),
            ("whatweb_scan", "corroborate technology fingerprint"),
        ],
        "domain": [
            ("whois_lookup", "registration and ownership"),
            ("dns_lookup", "resolve the domain"),
            ("subfinder_enum", "passive subdomain discovery"),
            ("httpx_probe", "probe the apex for a web surface"),
        ],
        "host": [
            ("dns_lookup", "reverse and forward records"),
            ("nmap_scan", "service discovery"),
        ],
        "network": [
            ("nmap_scan", "sweep the range for live services"),
        ],
    }

    def plan(
        self,
        profile: TargetProfile,
        already_run: Sequence[str],
        risk_ceiling: RiskLevel,
    ) -> List[PlannedStep]:
        """Return the tools worth running next, given current knowledge."""
        done = set(already_run)
        candidates: List[tuple] = []

        if not already_run:
            candidates.extend(self.SEED.get(profile.target_type, self.SEED["domain"]))

        # Adaptation: each observed fact can pull in a follow-up.
        techs = profile.technology_names()
        if profile.has_web_surface():
            candidates.append(("nuclei_scan", "template scan of the observed web surface"))
            candidates.append(("nikto_scan", "web server misconfiguration checks"))
        if any("wordpress" in t for t in techs):
            candidates.append(("wpscan_scan", "WordPress detected in the fingerprint"))
        if 443 in profile.open_ports() or profile.target.startswith("https://"):
            candidates.append(("testssl", "TLS configuration review of the HTTPS service"))
        if profile.open_ports() and "nmap_scan" not in done:
            candidates.append(("nmap_scan", "enumerate the services behind the open ports"))

        steps: List[PlannedStep] = []
        seen = set()
        for tool_name, reason in candidates:
            if tool_name in done or tool_name in seen:
                continue
            spec = T.get_tool_spec(tool_name)
            if spec is None:
                continue
            seen.add(tool_name)
            steps.append(PlannedStep(
                tool=tool_name,
                reason=reason,
                risk_level=spec.risk_level,
            ))
        return steps


@dataclass
class RunRecord:
    """The state of one autonomous run, safe to serialize for a dashboard."""

    id: str
    target: str
    status: RunStatus = RunStatus.RUNNING
    risk_ceiling: str = RiskLevel.ACTIVE.value
    max_steps: int = 20
    current_phase: str = "starting"
    steps_taken: int = 0
    executions: List[dict] = field(default_factory=list)
    withheld: List[dict] = field(default_factory=list)   # above the ceiling
    errors: List[dict] = field(default_factory=list)
    profile: Optional[dict] = None
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    @property
    def progress(self) -> int:
        if self.status is not RunStatus.RUNNING:
            return 100
        return min(99, int(100 * self.steps_taken / max(1, self.max_steps)))

    def to_dict(self) -> dict:
        return {
            "run_id": self.id,
            "target": self.target,
            "status": self.status.value,
            "risk_ceiling": self.risk_ceiling,
            "current_phase": self.current_phase,
            "progress": self.progress,
            "steps_taken": self.steps_taken,
            "max_steps": self.max_steps,
            "executions": self.executions,
            "recommended_next": self.withheld,
            "errors": self.errors,
            "profile": self.profile,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class AutonomousOrchestrator:
    """Run an adaptive assessment, every step within the risk ceiling."""

    def __init__(self, execution_service, finding_store=None, planner=None, profiler=None):
        self.exec = execution_service
        self.findings = finding_store
        self.planner = planner or AdaptivePlanner()
        self.profiler = profiler or Profiler()
        self._runs: Dict[str, RunRecord] = {}
        self._lock = threading.RLock()

    def list_runs(self) -> List[RunRecord]:
        with self._lock:
            return sorted(self._runs.values(), key=lambda r: r.started_at, reverse=True)

    def get_run(self, run_id: str) -> Optional[RunRecord]:
        with self._lock:
            return self._runs.get(run_id)

    def start(
        self,
        target: str,
        risk_ceiling: str = "active",
        max_steps: int = 20,
        run_async: bool = True,
    ) -> RunRecord:
        """Begin an autonomous run. Returns the record immediately when async."""
        try:
            ceiling = RiskLevel(risk_ceiling)
        except ValueError:
            ceiling = RiskLevel.ACTIVE

        # Autonomy never reaches intrusive or destructive, whatever is asked:
        # those require a human approval record, so the ceiling is clamped.
        if _RISK_ORDER[ceiling] > _RISK_ORDER[RiskLevel.ACTIVE]:
            ceiling = RiskLevel.ACTIVE

        record = RunRecord(
            id=uuid.uuid4().hex[:12],
            target=target,
            risk_ceiling=ceiling.value,
            max_steps=max(1, min(max_steps, 50)),
        )
        with self._lock:
            self._runs[record.id] = record

        if run_async:
            threading.Thread(
                target=self._run_loop,
                args=(record, ceiling),
                daemon=True,
            ).start()
        else:
            self._run_loop(record, ceiling)
        return record

    def _run_loop(self, record, ceiling):
        """The adaptive loop: plan from the profile, execute, observe, repeat."""
        try:
            profile = self.profiler.new_profile(record.target)
            already_run: List[str] = []

            while record.steps_taken < record.max_steps:
                steps = self.planner.plan(profile, already_run, ceiling)
                if not steps:
                    break

                record.current_phase = "planning"
                runnable = [s for s in steps if self._within_ceiling(s, ceiling)]
                self._record_withheld(record, steps, ceiling)

                if not runnable:
                    break

                progressed = False
                for step in runnable:
                    if record.steps_taken >= record.max_steps:
                        break
                    already_run.append(step.tool)
                    record.current_phase = f"running {step.tool}"
                    record.steps_taken += 1
                    progressed = True

                    result = self.exec.execute(
                        tool_name=step.tool,
                        params={self._target_param(step.tool): record.target},
                    )
                    self._absorb(record, profile, step, result)

                if not progressed:
                    break

            record.profile = profile.to_dict()
            record.status = RunStatus.COMPLETED
        except Exception as exc:  # noqa: BLE001 - recorded, run marked failed
            record.errors.append({"phase": record.current_phase, "error": str(exc)})
            record.status = RunStatus.FAILED
        finally:
            record.current_phase = "done"
            record.completed_at = datetime.utcnow()

    def _within_ceiling(self, step: PlannedStep, ceiling: RiskLevel) -> bool:
        try:
            level = RiskLevel(step.risk_level)
        except ValueError:
            level = RiskLevel.ACTIVE
        return _RISK_ORDER[level] <= _RISK_ORDER[ceiling]

    def _record_withheld(self, record, steps, ceiling):
        """Surface tools the planner wanted but the ceiling withholds."""
        for step in steps:
            if self._within_ceiling(step, ceiling):
                continue
            if any(w["tool"] == step.tool for w in record.withheld):
                continue
            record.withheld.append({
                "tool": step.tool,
                "reason": step.reason,
                "risk_level": step.risk_level,
                "withheld_because": (
                    f"{step.risk_level} exceeds the autonomous ceiling "
                    f"({ceiling.value}); requires human approval"
                ),
            })

    def _absorb(self, record, profile, step, result):
        """Fold one execution's outcome into the run, profile, and findings."""
        record.executions.append({
            "tool": step.tool,
            "reason": step.reason,
            "execution_id": result.get("execution_id"),
            "ok": result.get("ok", False),
            "status": result.get("status"),
            "code": result.get("code"),
        })

        if not result.get("ok"):
            # A denial or a missing binary is expected and not fatal; the loop
            # records it and moves on rather than aborting the assessment.
            record.errors.append({
                "tool": step.tool,
                "code": result.get("code"),
                "error": result.get("error"),
            })
            return

        parsed = T.parse_output(step.tool, result.get("output", "") or "")
        self.profiler.observe(profile, step.tool, parsed, result.get("execution_id", ""))

        if self.findings is not None and parsed is not None:
            self._findings_from(record, step, parsed, result)

    def _findings_from(self, record, step, parsed, result):
        """Turn structured tool output into normalized findings, conservatively."""
        from nexhunter.findings.models import Category, Finding, Severity

        records = parsed if isinstance(parsed, list) else [parsed]
        for item in records:
            if not isinstance(item, dict):
                continue
            # Only record what the tool actually reported as a finding. Open
            # ports and tech fingerprints are observations, not vulnerabilities.
            if item.get("severity") or item.get("template") or item.get("cve"):
                self.findings.add(Finding(
                    tool=step.tool,
                    target=record.target,
                    execution_id=result.get("execution_id", ""),
                    title=str(item.get("name") or item.get("template") or item.get("info") or "finding"),
                    category=Category.VULNERABILITY.value,
                    severity=item.get("severity", Severity.INFO.value),
                    evidence={k: v for k, v in item.items() if k != "raw"},
                    cve_ids=item.get("cve", []) if isinstance(item.get("cve"), list) else [],
                ))

    @staticmethod
    def _target_param(tool_name: str) -> str:
        spec = T.get_tool_spec(tool_name)
        return (spec.target_param if spec and spec.target_param else "target")
