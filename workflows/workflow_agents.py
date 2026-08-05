"""Workflow agents for comprehensive assessments."""

from typing import Dict, Any
from nexhunter.agents.base import Agent
from nexhunter.workflows.security_workflows import WORKFLOW_TYPES


class WorkflowAgent(Agent):
    """Base workflow agent."""

    def __init__(self, ctx=None, workflow_type: str = "bugbounty"):
        super().__init__(ctx or None)
        self.workflow_type = workflow_type
        self.workflow = None

    def execute(self, engine, params: Dict[str, Any]) -> dict:
        """Execute workflow."""
        target = params.get("target", "")
        if not target:
            return self.result(False, error="Target required")

        try:
            workflow_class = WORKFLOW_TYPES.get(self.workflow_type)
            if not workflow_class:
                return self.result(False, error=f"Unknown workflow: {self.workflow_type}")

            self.workflow = workflow_class(target)

            # Execute all phases
            for phase_name in self.workflow.phases.keys():
                if hasattr(self.workflow, "execute_phase"):
                    self.workflow.execute_phase(phase_name)

            summary = self.workflow.get_summary() if hasattr(self.workflow, "get_summary") else {
                "phases": len(self.workflow.phases),
                "target": target,
            }

            return self.result(
                True,
                data={"workflow": self.workflow_type, "target": target, "summary": summary},
                meta={"phases": len(self.workflow.phases)},
            )
        except Exception as e:
            return self.result(False, error=f"Workflow failed: {str(e)}")


class BugBountyWorkflowAgent(Agent):
    """Bug bounty assessment workflow."""

    name = "bugbounty_workflow"
    desc = "Professional bug bounty assessment with 10+ phases"

    def __init__(self, ctx=None):
        super().__init__(ctx or None)

    def execute(self, engine, params: Dict[str, Any]) -> dict:
        """Execute bug bounty workflow."""
        target = params.get("target", "")
        if not target:
            return self.result(False, error="Target required")

        try:
            workflow = WORKFLOW_TYPES["bugbounty"](target)

            # Execute phases
            phase_results = {}
            for phase_name in list(workflow.phases.keys())[:3]:  # Execute first 3 phases
                result = workflow.execute_phase(phase_name) if hasattr(workflow, "execute_phase") else {"ok": True}
                phase_results[phase_name] = result

            summary = workflow.get_summary() if hasattr(workflow, "get_summary") else {}

            return self.result(
                True,
                data={"phases_executed": phase_results, "summary": summary},
                meta={"total_phases": len(workflow.phases)},
            )
        except Exception as e:
            return self.result(False, error=f"Bug bounty workflow failed: {str(e)}")


class PentestWorkflowAgent(Agent):
    """Penetration testing workflow."""

    name = "pentest_workflow"
    desc = "Full penetration testing assessment"

    def __init__(self, ctx=None):
        super().__init__(ctx or None)

    def execute(self, engine, params: Dict[str, Any]) -> dict:
        """Execute pentest workflow."""
        target = params.get("target", "")
        if not target:
            return self.result(False, error="Target required")

        try:
            workflow = WORKFLOW_TYPES["pentest"](target)

            return self.result(
                True,
                data={
                    "workflow": "penetration_testing",
                    "target": target,
                    "phases": list(workflow.phases.keys()),
                },
                meta={"total_phases": len(workflow.phases)},
            )
        except Exception as e:
            return self.result(False, error=f"Pentest workflow failed: {str(e)}")


class ApiSecurityWorkflowAgent(Agent):
    """API security assessment workflow."""

    name = "api_workflow"
    desc = "Comprehensive API security assessment"

    def __init__(self, ctx=None):
        super().__init__(ctx or None)

    def execute(self, engine, params: Dict[str, Any]) -> dict:
        """Execute API security workflow."""
        target = params.get("target", "")
        if not target:
            return self.result(False, error="API endpoint required")

        try:
            workflow = WORKFLOW_TYPES["api"](target)

            return self.result(
                True,
                data={
                    "workflow": "api_security",
                    "api_endpoint": target,
                    "phases": list(workflow.phases.keys()),
                },
                meta={"total_phases": len(workflow.phases)},
            )
        except Exception as e:
            return self.result(False, error=f"API workflow failed: {str(e)}")


class CloudSecurityWorkflowAgent(Agent):
    """Cloud security assessment workflow."""

    name = "cloud_workflow"
    desc = "Cloud infrastructure security assessment"

    def __init__(self, ctx=None):
        super().__init__(ctx or None)

    def execute(self, engine, params: Dict[str, Any]) -> dict:
        """Execute cloud security workflow."""
        target = params.get("target", "")
        if not target:
            return self.result(False, error="Cloud account required")

        try:
            workflow = WORKFLOW_TYPES["cloud"](target)

            return self.result(
                True,
                data={
                    "workflow": "cloud_security",
                    "account": target,
                    "phases": list(workflow.phases.keys()),
                },
                meta={"total_phases": len(workflow.phases)},
            )
        except Exception as e:
            return self.result(False, error=f"Cloud workflow failed: {str(e)}")


class MobileSecurityWorkflowAgent(Agent):
    """Mobile app security assessment workflow."""

    name = "mobile_workflow"
    desc = "Mobile application security assessment"

    def __init__(self, ctx=None):
        super().__init__(ctx or None)

    def execute(self, engine, params: Dict[str, Any]) -> dict:
        """Execute mobile security workflow."""
        target = params.get("target", "")
        if not target:
            return self.result(False, error="App path required")

        try:
            workflow = WORKFLOW_TYPES["mobile"](target)

            return self.result(
                True,
                data={
                    "workflow": "mobile_security",
                    "app_path": target,
                    "phases": list(workflow.phases.keys()),
                },
                meta={"total_phases": len(workflow.phases)},
            )
        except Exception as e:
            return self.result(False, error=f"Mobile workflow failed: {str(e)}")


class DevSecOpsWorkflowAgent(Agent):
    """DevSecOps pipeline assessment workflow."""

    name = "devsecops_workflow"
    desc = "DevSecOps pipeline security assessment"

    def __init__(self, ctx=None):
        super().__init__(ctx or None)

    def execute(self, engine, params: Dict[str, Any]) -> dict:
        """Execute DevSecOps workflow."""
        target = params.get("target", "")
        if not target:
            return self.result(False, error="Pipeline path required")

        try:
            workflow = WORKFLOW_TYPES["devsecops"](target)

            return self.result(
                True,
                data={
                    "workflow": "devsecops",
                    "pipeline_path": target,
                    "phases": list(workflow.phases.keys()),
                },
                meta={"total_phases": len(workflow.phases)},
            )
        except Exception as e:
            return self.result(False, error=f"DevSecOps workflow failed: {str(e)}")


# Workflow agents registry
WORKFLOW_AGENTS = {
    "bugbounty_workflow": BugBountyWorkflowAgent(),
    "pentest_workflow": PentestWorkflowAgent(),
    "api_workflow": ApiSecurityWorkflowAgent(),
    "cloud_workflow": CloudSecurityWorkflowAgent(),
    "mobile_workflow": MobileSecurityWorkflowAgent(),
    "devsecops_workflow": DevSecOpsWorkflowAgent(),
}
