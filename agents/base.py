"""Agent base class with standardized result schema."""

from typing import Any


class Agent:
    """Base class for all agents with standardized result schema."""

    name = ""
    desc = ""
    param_schema = {}  # {param_name: (required: bool, type)}
    # True for agents that take attack-side actions (payload delivery, exploit
    # generation) reaching the network outside the ExecutionService gate. The
    # API refuses to run these unless intrusive tooling is explicitly enabled,
    # so offensive capability is opt-in and consistent with the tool registry's
    # own risk ceiling rather than exposed by default.
    offensive = False

    def __init__(self, ctx):
        self.ctx = ctx

    def validate_params(self, params: dict) -> tuple[bool, str | None]:
        """Validate parameters against schema. Return (ok, error_msg)."""
        for param, (required, param_type) in self.param_schema.items():
            if required and param not in params:
                return False, f"missing required param: {param}"
            if param in params and not isinstance(params[param], param_type):
                return False, f"param {param} must be {param_type.__name__}, got {type(params[param]).__name__}"
        return True, None

    def result(self, ok: bool, data: Any = None, error: str | None = None, meta: dict | None = None) -> dict:
        """Standardized result format: {ok, data/error, meta, agent}."""
        r = {"ok": ok, "agent": self.name}
        if ok and data is not None:
            r["data"] = data
        if not ok and error:
            r["error"] = error
        if meta:
            r["meta"] = meta
        return r

    def run(self, **params):
        """Run agent. Subclasses must implement."""
        raise NotImplementedError
