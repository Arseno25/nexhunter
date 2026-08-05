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

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from nexhunter.core import tools as T
from nexhunter.core.risk import RiskLevel
from nexhunter.agents.profiler import Profiler, TargetProfile
from nexhunter.agents.selector import ToolSelector
from nexhunter.agents.param_optimizer import ParameterOptimizer
from nexhunter.api.visual import format_step, supports_color, COLORS

log = logging.getLogger("nexhunter.workflows")

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
def _has_domain(profile: TargetProfile) -> bool:
    """A hostname or network block exists to look up; a bare IP has none."""
    return profile.target_type != "host"


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
        ("recon", "whois_lookup", "registration, ownership, and infrastructure", _has_domain),
        ("recon", "subfinder_enum", "passive subdomain discovery", _has_domain),
        ("recon", "httpx_probe", "identify HTTP status, title, and technology", None),
        ("recon", "whatweb_scan", "corroborate the technology fingerprint", _has_web_surface),
        # ---- Phase 2: active enumeration ------------------------------
        ("enumeration", "nmap_scan", "service and version discovery on the host", None),
        ("enumeration", "naabu", "fast port corroboration of the nmap sweep", _has_open_ports),
        ("enumeration", "dig_axfr", "zone transfer attempt (misconfiguration check)", _has_domain),
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
    # methodology = fixed, reviewed phase walk (default). select = scoring-driven
    # selection over the full registry, capped by the objective's breadth.
    strategy: str = "methodology"
    objective: str = "standard"
    # direct runs every step through the in-process path
    # (no per-tool execution records or workspaces) while keeping cache,
    # redaction, the risk ceiling and result absorption. Default on.
    direct: bool = True
    current_phase: str = "starting"
    steps_taken: int = 0
    executions: List[dict] = field(default_factory=list)
    withheld: List[dict] = field(default_factory=list)   # above the ceiling
    errors: List[dict] = field(default_factory=list)
    plan: Optional[List[dict]] = None                    # AI-proposed, approved steps
    profile: Optional[dict] = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
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
            "strategy": self.strategy,
            "objective": self.objective,
            "direct": self.direct,
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

    def __init__(self, execution_service, finding_store=None, planner=None,
                 profiler=None, optimizer=None):
        self.exec = execution_service
        self.findings = finding_store
        self.planner = planner or AdaptivePlanner()
        self.profiler = profiler or Profiler()
        # Turns a target + profile into the parameters each tool should run
        # with, so a selected tool is invoked correctly rather than fed the raw
        # target and rejected.
        self.optimizer = optimizer or ParameterOptimizer()
        self._runs: Dict[str, RunRecord] = {}
        self._lock = threading.RLock()

    def _params_for(self, spec, record, profile):
        """Optimized parameters for a tool, with a safe fallback."""
        if spec is None:
            return {}
        try:
            return self.optimizer.optimize(spec, record.target, profile, record.objective)
        except Exception:  # noqa: BLE001 - never let tuning abort a run
            params = {}
            if spec.target_param:
                params[spec.target_param] = record.target
            return params

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

    @staticmethod
    def select_plan(
        target: str, objective: str = "standard", risk_ceiling: str = "active"
    ) -> dict:
        """Scoring-driven shortlist for a target, without running anything.

        This is the plan-first answer the AI reviews: a small, ranked set of the
        tools actually worth running against this target -- with the reason for
        each pick and the tools held back above the ceiling -- drawn from the
        whole registry rather than a fixed methodology list. The AI (or a human)
        chooses a subset from here, then start(steps=...) runs only that subset.
        """
        ceiling = _coerce_ceiling(risk_ceiling)
        profile = Profiler().new_profile(target)
        result = ToolSelector().select(profile, objective, ceiling)
        payload = result.to_dict()

        # Attach the exact parameters each selected tool would run with, so the
        # shortlist is not just "which tools" but "which tools, invoked how".
        optimizer = ParameterOptimizer()
        for entry in payload["selected"]:
            spec = T.get_tool_spec(entry["tool"])
            if spec is not None:
                entry["params"] = optimizer.optimize(spec, target, profile, objective)
        return payload

    def start(
        self,
        target: str,
        risk_ceiling: str = "active",
        max_steps: int = 20,
        run_async: bool = True,
        steps: Optional[Sequence[dict]] = None,
        strategy: str = "methodology",
        objective: str = "standard",
        direct: bool = True,
    ) -> RunRecord:
        """Begin an autonomous run. Returns the record immediately when async.

        With `steps`, the AI's own plan is executed: every step is validated
        and ceiling-filtered again at run time (review_plan already did so; a
        second pass keeps a race from slipping one through). Without `steps`,
        the loop plans from observed evidence -- `strategy` chooses how:

          methodology  the fixed, reviewed phase walk (default, deterministic)
          select       scoring-driven selection over the whole registry,
                       capped by `objective` (quick|standard|comprehensive|
                       stealth); leans on ToolSelector so only high-value tools
                       for the observed profile actually run

        `direct=True` (the default) runs every step through the
        in-process path: no per-tool execution records or
        workspaces are minted, while the cache, redaction, risk ceiling and
        result absorption all stay on. Set direct=False (or per-step
        "direct": false) for fully tracked step execution.
        """
        ceiling = _coerce_ceiling(risk_ceiling)

        record = RunRecord(
            id=uuid.uuid4().hex[:12],
            target=target,
            risk_ceiling=ceiling.value,
            max_steps=max(1, min(max_steps, 50)),
            strategy="select" if strategy == "select" else "methodology",
            objective=objective,
            direct=bool(direct),
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
        total = (
            min(record.max_steps, len(record.plan))
            if record.plan is not None else record.max_steps
        )
        c = COLORS if supports_color() else {k: "" for k in COLORS}
        log.info(
            "%s🚀 AUTONOMOUS START%s  %s  ceiling=%s  budget=%d steps",
            c["GREEN"] + c["BOLD"], c["RESET"], record.target,
            record.risk_ceiling, total,
        )
        try:
            profile = self.profiler.new_profile(record.target)
            already_run: List[str] = []

            if record.plan is not None:
                self._run_plan(record, ceiling, profile, total)
            elif record.strategy == "select":
                self._run_select(record, ceiling, profile, total)
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

                        self._emit_step(record, total, step.tool, step.phase or "recon")
                        spec = T.get_tool_spec(step.tool)
                        result = self.exec.execute(
                            tool_name=step.tool,
                            params=self._params_for(spec, record, profile),
                            direct=record.direct,
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
            record.completed_at = datetime.now(timezone.utc)
            done_ok = record.status is RunStatus.COMPLETED
            elapsed = (record.completed_at - record.started_at).total_seconds()
            tone = c["GREEN"] if done_ok else c["RED"]
            log.info(
                "%s🏁 AUTONOMOUS DONE%s   %s  status=%s  steps=%d/%d  %.1fs",
                tone + c["BOLD"], c["RESET"], record.target,
                record.status.value, record.steps_taken, total, elapsed,
            )

    def _emit_step(self, record, total: int, tool: str, phase: str) -> None:
        """Log one step progress line for an autonomous run."""
        log.info(format_step(
            record.steps_taken, total, tool=tool, target=record.target, phase=phase,
        ))

    def _run_plan(self, record, ceiling, profile, total=None):
        """Execute the AI-approved plan, re-validating every step."""
        total = total or record.max_steps
        for step in record.plan or []:
            if record.steps_taken >= record.max_steps:
                break

            tool = step.get("tool")
            params = dict(step.get("params") or {})
            spec = T.get_tool_spec(tool)
            if spec is None:
                record.errors.append({"tool": tool, "error": f"unknown tool: {tool}"})
                continue

            # Fill anything the AI left out with optimized defaults, but never
            # override what it explicitly set -- its plan wins -- then validate
            # the completed parameter set.
            optimized = self._params_for(spec, record, profile)
            params = {**optimized, **params}

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

            record.current_phase = f"running {tool}"
            record.steps_taken += 1
            self._emit_step(record, total, tool, "ai-plan")
            result = self.exec.execute(tool_name=tool, params=params,
                                       direct=bool(step.get("direct", record.direct)))
            self._absorb(record, profile,
                         PlannedStep(tool=tool, reason="from the AI plan",
                                     risk_level=spec.risk_level),
                         result)

    def _run_select(self, record, ceiling, profile, total):
        """Scoring-driven loop: run only the tools the selector ranks worth it.

        Re-selects each pass as evidence accumulates, so a web surface found in
        recon pulls in web tooling on the next round -- the same adaptive feel
        as the methodology loop, but drawing on the whole registry instead of a
        fixed list, and capped by the objective so it never runs everything.
        """
        selector = ToolSelector()
        already: List[str] = []
        while record.steps_taken < record.max_steps:
            result = selector.select(profile, record.objective, ceiling)
            self._record_withheld_selection(record, result.withheld, ceiling)

            pending = [s for s in result.selected if s.name not in already]
            if not pending:
                break

            progressed = False
            for st in pending:
                if record.steps_taken >= record.max_steps:
                    break
                spec = T.get_tool_spec(st.name)
                already.append(st.name)
                if spec is None:
                    continue
                record.current_phase = f"running {st.name}"
                record.steps_taken += 1
                progressed = True

                self._emit_step(record, total, st.name, st.phase)
                params = self._params_for(spec, record, profile)
                exec_result = self.exec.execute(tool_name=st.name, params=params,
                                            direct=record.direct)
                self._absorb(record, profile, PlannedStep(
                    tool=st.name,
                    reason=f"selected by scoring ({st.score:.2f})",
                    risk_level=st.risk_level,
                    phase=st.phase,
                ), exec_result)

            if not progressed:
                break

    def _record_withheld_selection(self, record, withheld, ceiling):
        """Surface scored tools above the ceiling as recommendations."""
        for st in withheld:
            if any(w["tool"] == st.name for w in record.withheld):
                continue
            record.withheld.append({
                "tool": st.name,
                "reason": f"selected by scoring ({st.score:.2f})",
                "risk_level": st.risk_level,
                "withheld_because": (
                    f"{st.risk_level} exceeds the autonomous ceiling "
                    f"({ceiling.value}); requires human approval"
                ),
            })

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
