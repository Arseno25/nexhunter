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


def _coerce_ceiling(risk_ceiling: str) -> RiskLevel:
    """Parse a ceiling, clamped so autonomy never reaches intrusive."""
    try:
        ceiling = RiskLevel(risk_ceiling)
    except ValueError:
        ceiling = RiskLevel.ACTIVE
    if _RISK_ORDER[ceiling] > _RISK_ORDER[RiskLevel.ACTIVE]:
        ceiling = RiskLevel.ACTIVE
    return ceiling


# Planner gates: evidence predicates over a target profile. Each decides
# whether a methodology phase is warranted at all.
def _is_domain(profile: TargetProfile) -> bool:
    return profile.target_type in ("domain", "network")


def _has_web_surface(profile: TargetProfile) -> bool:
    return profile.has_web_surface()


def _has_open_ports(profile: TargetProfile) -> bool:
    return bool(profile.open_ports())


def _has_tls(profile: TargetProfile) -> bool:
    return 443 in profile.open_ports() or profile.target.startswith("https://")


def _is_wordpress(profile: TargetProfile) -> bool:
    return any("wordpress" in t for t in profile.technology_names())


class RunStatus(Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass
class PlanStep:
    """One AI-proposed step: a tool plus its parameters."""

    tool: str
    params: dict = field(default_factory=dict)


def review_plan(target: str, steps, risk_ceiling: str = "active") -> dict:
    """Validate AI-proposed steps without executing anything.

    Every step is looked up in the registry, its parameters are typed-validated,
    and its risk level is checked against the ceiling. The result is three
    lists: approved (validated, within the ceiling), withheld (valid, but above
    the ceiling -- needs a human), and invalid (unknown tool or bad parameters).

    This is the whole point of the plan-first flow: the AI can propose a plan,
    but nothing it proposed reaches the OS unvalidated.
    """
    ceiling = _coerce_ceiling(risk_ceiling)

    approved, withheld, invalid = [], [], []
    for step in steps or []:
        if not isinstance(step, dict):
            invalid.append({"tool": str(step), "reason": "step must be an object with tool and params"})
            continue
        tool = step.get("tool")
        params = step.get("params") or {}
        spec = T.get_tool_spec(tool)
        if spec is None:
            invalid.append({"tool": tool, "reason": f"unknown tool: {tool}"})
            continue
        ok, err = spec.validate(params)
        if not ok:
            invalid.append({"tool": tool, "params": params, "reason": err})
            continue
        try:
            level = RiskLevel(spec.risk_level)
        except ValueError:
            level = RiskLevel.ACTIVE
        if _RISK_ORDER[level] > _RISK_ORDER[ceiling]:
            withheld.append({
                "tool": tool, "params": params, "risk_level": spec.risk_level,
                "reason": f"{spec.risk_level} exceeds the autonomous ceiling ({ceiling.value}); "
                          "requires human approval",
            })
            continue
        approved.append({"tool": tool, "params": params, "risk_level": spec.risk_level})

    return {
        "target": target,
        "risk_ceiling": ceiling.value,
        "approved": approved,
        "withheld": withheld,
        "invalid": invalid,
    }


@dataclass
class PlannedStep:
    """A tool the planner wants to run next, and why."""

    tool: str
    reason: str
    risk_level: str
    phase: str = ""


class AdaptivePlanner:
    """Choose the next tools from what has been observed so far.

    Deterministic on purpose: the same profile yields the same plan, so an
    autonomous run is reproducible and reviewable. The AI can propose a target
    and a ceiling; it does not get to invent the tool list.

    The plan follows a real assessment methodology, phase by phase:

        1. recon          passive footprint: DNS, WHOIS, subdomains, web probe
        2. enumeration    active service discovery behind open ports
        3. web_enum       content, endpoints, parameters on the web surface
        4. assessment     targeted checks: templates, TLS, tech-specific scans
        5. exploitation   intrusive follow-ups - always planned, never run
                          autonomously; the risk ceiling withholds them for a
                          human, which is exactly where they belong

    A phase is only entered on evidence from the phase before it. A domain
    that resolves to nothing never reaches enumeration; a host with no web
    ports never reaches web_enum. Exploitation-class steps are still planned
    (a senior operator knows what comes next) but the autonomy ceiling
    surfaces them as recommendations, never as executed commands.
    """

    # (phase, tool, reason, gate). Gates are predicates over the profile;
    # None means "no gate".
    METHODOLOGY: tuple = (
        # ---- Phase 1: passive recon ----------------------------------
        ("recon", "dns_lookup", "resolve the target's records", None),
        ("recon", "whois_lookup", "registration, ownership, and infrastructure", _is_domain),
        ("recon", "subfinder_enum", "passive subdomain discovery", _is_domain),
        ("recon", "httpx_probe", "identify HTTP status, title, and technology", None),
        ("recon", "whatweb_scan", "corroborate the technology fingerprint", _has_web_surface),
        # ---- Phase 2: active enumeration ------------------------------
        ("enumeration", "nmap_scan", "service and version discovery on the host", None),
        ("enumeration", "naabu", "fast port corroboration of the nmap sweep", _has_open_ports),
        ("enumeration", "dig_axfr", "zone transfer attempt (misconfiguration check)", _is_domain),
        # ---- Phase 3: web surface enumeration --------------------------
        ("web_enum", "katana_crawl", "crawl the web surface for endpoints and JS", _has_web_surface),
        ("web_enum", "waybackurls", "historical URLs for hidden endpoints", _has_web_surface),
        ("web_enum", "gau", "URL discovery across passive sources", _has_web_surface),
        ("web_enum", "paramspider", "parameter discovery for injection surface", _has_web_surface),
        ("web_enum", "feroxbuster", "content discovery against the web root", _has_web_surface),
        # ---- Phase 4: targeted assessment ------------------------------
        ("assessment", "nuclei_scan", "template scan of the observed web surface", _has_web_surface),
        ("assessment", "nikto_scan", "web server misconfiguration checks", _has_web_surface),
        ("assessment", "testssl", "TLS configuration review of the HTTPS service", _has_tls),
        ("assessment", "sslyze", "cipher and protocol policy review", _has_tls),
        ("assessment", "wpscan_scan", "WordPress detected in the fingerprint", _is_wordpress),
        ("assessment", "dalfox_xss", "XSS check against discovered parameters", _has_web_surface),
        # ---- Phase 5: exploitation (withheld by the ceiling) ------------
        ("exploitation", "sqlmap_scan", "auto-injection testing on the parameter surface", _has_web_surface),
        ("exploitation", "ffuf_scan", "fuzzing for hidden parameters and vhosts", _has_web_surface),
    )

    def plan(
        self,
        profile: TargetProfile,
        already_run: Sequence[str],
        risk_ceiling: RiskLevel,
    ) -> List[PlannedStep]:
        """Return the tools worth running next, given current knowledge."""
        done = set(already_run)
        steps: List[PlannedStep] = []
        seen = set()

        for phase, tool_name, reason, gate in self.METHODOLOGY:
            if tool_name in done or tool_name in seen:
                continue
            if gate is not None and not gate(profile):
                continue
            spec = T.get_tool_spec(tool_name)
            if spec is None:
                continue
            seen.add(tool_name)
            steps.append(PlannedStep(
                tool=tool_name,
                reason=reason,
                risk_level=spec.risk_level,
                phase=phase,
            ))
        return steps

    def recommend(self, target: str, risk_ceiling: str = "active") -> dict:
        """A reviewable methodology plan for a target, without running anything.

        This is the plan-first answer: give the planner a target and get the
        phases a senior operator would walk, with the reason for each tool.
        Exploitation steps are listed under 'withheld' - planned, but gated
        behind human approval.
        """
        ceiling = _coerce_ceiling(risk_ceiling)
        profile = Profiler().new_profile(target)
        steps = self.plan(profile, [], ceiling)

        phases: Dict[str, List[dict]] = {}
        withheld: List[dict] = []
        for step in steps:
            entry = {"tool": step.tool, "reason": step.reason, "risk_level": step.risk_level}
            if _RISK_ORDER[RiskLevel(step.risk_level)] > _RISK_ORDER[ceiling]:
                withheld.append({**entry, "requires": "human approval"})
            else:
                phases.setdefault(step.phase, []).append(entry)

        return {
            "target": target,
            "risk_ceiling": ceiling.value,
            "phases": phases,
            "withheld": withheld,
        }


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
    plan: Optional[List[dict]] = None                    # AI-proposed, approved steps
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
            "plan": self.plan,
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

    @staticmethod
    def review_plan(target: str, steps, risk_ceiling: str = "active") -> dict:
        """Validate AI-proposed steps without executing anything."""
        return review_plan(target, steps, risk_ceiling)

    @staticmethod
    def recommend_plan(target: str, risk_ceiling: str = "active") -> dict:
        """A methodology-driven plan for a target, without running anything.

        Recon first, then enumeration, web enumeration, assessment, and the
        exploitation follow-ups a senior operator would schedule next - each
        gated on the evidence the phase before it would produce. Exploitation
        steps are listed under 'withheld': planned, but gated behind human
        approval by the autonomy ceiling.
        """
        return AdaptivePlanner().recommend(target, risk_ceiling)

    def start(
        self,
        target: str,
        risk_ceiling: str = "active",
        max_steps: int = 20,
        run_async: bool = True,
        steps: Optional[Sequence[dict]] = None,
    ) -> RunRecord:
        """Begin an autonomous run. Returns the record immediately when async.

        With `steps`, the AI's own plan is executed: every step is validated
        and ceiling-filtered again at run time (review_plan already did so; a
        second pass keeps a race from slipping one through). Without `steps`,
        the adaptive loop plans from observed evidence.
        """
        ceiling = _coerce_ceiling(risk_ceiling)

        record = RunRecord(
            id=uuid.uuid4().hex[:12],
            target=target,
            risk_ceiling=ceiling.value,
            max_steps=max(1, min(max_steps, 50)),
        )
        with self._lock:
            self._runs[record.id] = record

        if steps:
            record.plan = list(steps)

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
        """The adaptive loop: plan from the profile, execute, observe, repeat.

        With a plan, the loop executes exactly the approved steps instead.
        """
        try:
            profile = self.profiler.new_profile(record.target)
            already_run: List[str] = []

            if record.plan is not None:
                self._run_plan(record, ceiling, profile)
            else:
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

    def _run_plan(self, record, ceiling, profile):
        """Execute the AI-approved plan, re-validating every step."""
        for step in record.plan or []:
            if record.steps_taken >= record.max_steps:
                break

            tool = step.get("tool")
            params = dict(step.get("params") or {})
            spec = T.get_tool_spec(tool)
            if spec is None:
                record.errors.append({"tool": tool, "error": f"unknown tool: {tool}"})
                continue

            ok, err = spec.validate(params)
            if not ok:
                record.errors.append({"tool": tool, "error": err})
                continue

            try:
                level = RiskLevel(spec.risk_level)
            except ValueError:
                level = RiskLevel.ACTIVE
            if _RISK_ORDER[level] > _RISK_ORDER[ceiling]:
                self._record_withheld(record, [
                    PlannedStep(tool=tool, reason="AI plan step above the ceiling",
                                risk_level=spec.risk_level),
                ], ceiling)
                continue

            # A plan step without the target parameter gets the run target,
            # the same default the adaptive loop applies.
            if spec.target_param and spec.target_param not in params:
                params[spec.target_param] = record.target

            record.current_phase = f"running {tool}"
            record.steps_taken += 1
            result = self.exec.execute(tool_name=tool, params=params)
            self._absorb(record, profile,
                         PlannedStep(tool=tool, reason="from the AI plan",
                                     risk_level=spec.risk_level),
                         result)

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
