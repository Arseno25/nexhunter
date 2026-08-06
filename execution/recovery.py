"""Recovery engine: classify tool failures and pick the next action.

Resilience without any extra dependency:

  * classify an outcome (timeout, network unreachable, rate-limited,
    permission denied, tool missing, resource exhausted, unknown) from the
    error text and exit code;
  * recover along the cheapest viable path: retry with backoff, retry with a
    reduced scope (fewer threads, gentler timing, a smaller port range),
    switch to an alternative tool that observes the same thing, or stop and
    let a human decide.

This layer only decides and rewrites parameters -- command execution itself
still goes through the ExecutionService so the one-execution-path invariant
is preserved.
"""

from __future__ import annotations

import enum
import logging
import time

from nexhunter.core import tools as T

log = logging.getLogger("nexhunter.recovery")


class ErrorType(enum.Enum):
    TIMEOUT = "timeout"
    NETWORK_UNREACHABLE = "network_unreachable"
    RATE_LIMITED = "rate_limited"
    PERMISSION_DENIED = "permission_denied"
    TOOL_NOT_FOUND = "tool_not_found"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    UNKNOWN = "unknown"


class RecoveryAction(enum.Enum):
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    RETRY_WITH_REDUCED_SCOPE = "retry_with_reduced_scope"
    SWITCH_TO_ALTERNATIVE_TOOL = "switch_to_alternative_tool"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    NONE = "none"


_ERROR_FINGERPRINTS: tuple = (
    # (ErrorType, (substrings matched in lowercased output+stderr))
    (ErrorType.TIMEOUT, ("timed out", "timeout", "deadline exceeded")),
    (ErrorType.NETWORK_UNREACHABLE, (
        "network is unreachable", "connection refused", "connection reset",
        "no route to host", "could not resolve host", "dns lookup failed",
        "unreachable",
    )),
    (ErrorType.RATE_LIMITED, (
        "rate limit", "too many requests", "throttl", "retry after",
        "cloudflare",
    )),
    (ErrorType.PERMISSION_DENIED, (
        "permission denied", "not permitted", "operation not permitted",
        "requires root", "sudo", "unauthorized", "access denied",
    )),
    (ErrorType.TOOL_NOT_FOUND, (
        "not found on path", "no such file or directory", "command not found",
        "not installed", "binary not found",
    )),
    (ErrorType.RESOURCE_EXHAUSTED, (
        "out of memory", "cannot allocate memory", "no space left on device",
        "too many open files", "resource temporarily unavailable",
    )),
)

_DEFAULT_ACTIONS: dict[ErrorType, list[RecoveryAction]] = {
    ErrorType.TIMEOUT: [
        RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
        RecoveryAction.RETRY_WITH_BACKOFF,
    ],
    ErrorType.NETWORK_UNREACHABLE: [
        RecoveryAction.RETRY_WITH_BACKOFF,
        RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL,
    ],
    ErrorType.RATE_LIMITED: [
        RecoveryAction.RETRY_WITH_BACKOFF,
        RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
    ],
    ErrorType.PERMISSION_DENIED: [RecoveryAction.ESCALATE_TO_HUMAN],
    ErrorType.TOOL_NOT_FOUND: [RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL],
    ErrorType.RESOURCE_EXHAUSTED: [
        RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
        RecoveryAction.ESCALATE_TO_HUMAN,
    ],
    ErrorType.UNKNOWN: [RecoveryAction.ESCALATE_TO_HUMAN],
}

_ALTERNATIVES: dict[str, tuple] = {
    "port_scan": ("nmap_scan", "masscan", "rustscan"),
    "dns_enum": ("dns_lookup", "dig_axfr", "dnsrecon"),
    "subdomain": ("subfinder_enum", "amass_enum", "assetfinder", "crt_sh"),
    "http_probe": ("httpx_probe", "curl_headers", "probe"),
    "dir_brute": ("gobuster_dir", "dirsearch", "ffuf_scan", "feroxbuster"),
    "web_scan": ("nuclei_scan", "nikto_scan", "whatweb_scan"),
    "xss": ("dalfox_xss", "xsstrike"),
    "sqli": ("sqlmap_scan", "nosqlmap"),
}


def _guess_goal(tool: str) -> str | None:
    """Map a tool name to an alternatives group (best effort)."""
    for goal, members in _ALTERNATIVES.items():
        if tool in members:
            return goal
    for goal in _ALTERNATIVES:
        if goal in tool:
            return goal
    return None


def classify_error(message: str, exit_code: int | None = None,
                   stdout: str = "") -> ErrorType:
    """Classify a failure from error text, exit code, and captured stdout."""
    blob = f"{message or ''} {stdout or ''}".lower()
    for error_type, fingerprints in _ERROR_FINGERPRINTS:
        if any(fp in blob for fp in fingerprints):
            return error_type
    if exit_code not in (None, 0):
        return ErrorType.UNKNOWN
    return ErrorType.UNKNOWN


def recovery_plan(error_type: ErrorType,
                  attempts_used: int) -> list[RecoveryAction]:
    """Recovery actions still available for an error type."""
    actions = list(
        _DEFAULT_ACTIONS.get(error_type) or _DEFAULT_ACTIONS[ErrorType.UNKNOWN]
    )
    remaining = [a for i, a in enumerate(actions) if i >= attempts_used]
    return remaining or [RecoveryAction.ESCALATE_TO_HUMAN]


def reduced_scope_params(tool: str, params: dict) -> dict:
    """Rewrite params to a smaller, gentler scope for a retry."""
    p = dict(params)
    try:
        threads = int(p.get("threads", 0))
        if threads > 1:
            p["threads"] = str(max(1, threads // 2))
    except (TypeError, ValueError):
        p["threads"] = "1"
    if "timing" in p and str(p["timing"]) in ("T4", "4", "3"):
        p["timing"] = "2"
    if "rate" in p:
        try:
            p["rate"] = str(max(100, int(p["rate"]) // 4))
        except (TypeError, ValueError):
            p["rate"] = "100"
    if p.get("ports", "1-65535") == "1-65535":
        p["ports"] = "80,443,22,3389"
    return p


def alternative_tool(tool: str) -> str | None:
    """Best alternative tool, or None if none is registered."""
    goal = _guess_goal(tool)
    if not goal:
        return None
    for candidate in _ALTERNATIVES[goal]:
        if candidate != tool and T.get_tool_spec(candidate) is not None:
            return candidate
    return None


def backoff_seconds(attempt: int, base: float = 1.5, cap: float = 30.0) -> float:
    """Exponential backoff, deterministic per attempt number."""
    return min(cap, base * (2 ** max(0, attempt - 1)))


class ExecutionRecovery:
    """Stateful retry loop around a single tool call.

    Runs the tool through the ExecutionService up to `max_attempts` times,
    choosing each retry's strategy from the failure class, and returns the
    final result together with the full recovery trail.
    """

    def __init__(self, service=None, run_fn=None, max_attempts: int = 3,
                 use_backoff: bool = True):
        """`service` is an ExecutionService; `run_fn(tool, params) -> result`
        is the lower-level alternative (e.g. an agent context's run_tool).
        Exactly one must be provided."""
        if service is None and run_fn is None:
            raise ValueError("ExecutionRecovery needs a service or a run_fn")
        self.service = service
        self.run_fn = run_fn
        self.max_attempts = max(1, int(max_attempts))
        self.use_backoff = use_backoff

    def _run_once(self, tool: str, params: dict, direct: bool) -> dict:
        if self.run_fn is not None:
            return self.run_fn(tool, params)
        return self.service.execute(
            tool_name=tool, params=params, direct=direct, no_cache=True
        )

    def execute(self, tool: str, params: dict, direct: bool = True) -> dict:
        """Run `tool` with recovery. The result gains a `recovery` summary."""
        attempts = 0
        last: dict | None = None
        current_tool = tool
        current_params = dict(params or {})
        trail: list[dict] = []
        succeeded = False
        # How many times each error type's recovery plan has been consumed.
        # Recovery always walks a plan from the cheapest strategy upward, and
        # a plan is per error type, not per global attempt count.
        used_plan: dict[ErrorType, int] = {}

        while attempts < self.max_attempts:
            attempts += 1
            # A retry must bypass the cache: the failed first answer is still
            # cached, so a fresh attempt would otherwise get the same result.
            run = self._run_once(current_tool, current_params, direct)
            last = run

            if run.get("ok") and run.get("exit") == 0:
                succeeded = True
                break

            error_type = classify_error(
                run.get("error", ""), run.get("exit"),
                run.get("stderr", "") or run.get("output", ""),
            )
            if attempts >= self.max_attempts:
                trail.append({
                    "attempt": attempts, "tool": current_tool,
                    "error_type": error_type.value, "outcome": "exhausted",
                })
                break

            consumed = used_plan.get(error_type, 0)
            actions = recovery_plan(error_type, consumed)
            action = actions[0]
            action = actions[0]
            entry: dict = {
                "attempt": attempts, "tool": current_tool,
                "error_type": error_type.value,
                "error_snippet": (run.get("error")
                                  or run.get("stderr")
                                  or run.get("output") or "")[:200],
            }

            switched = False
            if action is RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL:
                alt = alternative_tool(current_tool)
                if alt is not None:
                    spec = T.get_tool_spec(alt)
                    if spec is not None:
                        current_tool = alt
                        entry["switched_to"] = alt
                        switched = True

            if not switched:
                if action is RecoveryAction.ESCALATE_TO_HUMAN:
                    entry["action"] = action.value
                    entry["outcome"] = "escalated"
                    trail.append(entry)
                    break
                if action == RecoveryAction.RETRY_WITH_REDUCED_SCOPE:
                    current_params = reduced_scope_params(
                        current_tool, current_params
                    )
                    entry["action"] = action.value
                elif action == RecoveryAction.RETRY_WITH_BACKOFF:
                    entry["action"] = action.value
                    if self.use_backoff:
                        time.sleep(backoff_seconds(attempts))
                else:
                    entry["action"] = RecoveryAction.ESCALATE_TO_HUMAN.value
                    entry["outcome"] = "escalated"
                    trail.append(entry)
                    break
            else:
                entry["action"] = RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL.value

            trail.append(entry)
            used_plan[error_type] = used_plan.get(error_type, 0) + 1

        result = dict(last or {"ok": False, "error": "no attempt ran"})
        result["recovery"] = {
            "attempts": attempts,
            "exhausted": not succeeded,
            "trail": trail,
        }
        return result
