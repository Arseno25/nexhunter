"""nexhunter.agents - AI agent layer with auto-discovery."""

import importlib
import pkgutil

from nexhunter.agents.base import Agent

AGENTS: dict[str, type[Agent]] = {}


def _discover_agents():
    """Auto-discover and register agents from modules."""
    for _m in pkgutil.iter_modules(__path__):
        try:
            _mod = importlib.import_module(f"{__name__}.{_m.name}")
            for _obj in vars(_mod).values():
                if isinstance(_obj, type) and issubclass(_obj, Agent) and _obj is not Agent and _obj.name:
                    AGENTS[_obj.name] = _obj
        except ImportError:
            # Log but don't fail discovery if one module has issues
            pass


_discover_agents()


def run_agent(engine, name: str, params: dict = None) -> dict:
    """Run agent by name with standardized error handling."""
    params = params or {}
    cls = AGENTS.get(name)
    if not cls:
        return {"ok": False, "agent": name, "error": f"unknown agent: {name}"}
    try:
        agent = cls(engine)
        ok, err = agent.validate_params(params)
        if not ok:
            return agent.result(ok=False, error=err)
        result = agent.run(**params)
        return result
    except Exception as e:
        return {"ok": False, "agent": name, "error": str(e)}
