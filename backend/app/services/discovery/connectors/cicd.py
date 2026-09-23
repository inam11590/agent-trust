"""CI/CD Workflow Discovery Connector (Step 29).

Enforces:
- Pure static parsing of workflow definitions (.github/workflows, gitlab-ci.yml)
- Zero pipeline execution
- Zero secrets disclosure
"""

from __future__ import annotations

import re
from typing import Any, Dict, List
from app.services.discovery.connectors.base import BaseDiscoveryConnector, DiscoveredResource


class CicdDiscoveryConnector(BaseDiscoveryConnector):
    """Inspects CI/CD pipeline definitions for AI agent deployments and package installations."""

    def test_connection(self) -> Dict[str, Any]:
        platform = self.config.get("platform", "GITHUB_ACTIONS")
        return {
            "status": "CONNECTED",
            "platform": platform,
            "read_only": True,
            "pipeline_execution": False,
        }

    def scan(self) -> List[DiscoveredResource]:
        pipeline_name = self.config.get("pipeline_name", "ai-agent-deploy")
        workflow_content = self.config.get("workflow_yaml", "")
        environment = self.config.get("environment", "staging")

        dependencies: List[str] = []
        env_var_names: List[str] = []

        # Find package installations like `pip install ...` or `npm install ...`
        for line in workflow_content.splitlines():
            line = line.strip()
            if "pip install" in line:
                pkgs = line.split("pip install", 1)[1].split()
                for p in pkgs:
                    if not p.startswith("-"):
                        dependencies.append(p.strip())
            elif "npm install" in line or "npm i" in line:
                pkgs = re.split(r"npm (?:install|i)", line)[1].split()
                for p in pkgs:
                    if not p.startswith("-"):
                        dependencies.append(p.strip())
            
            # Find env blocks (variable names only!)
            if line.startswith("OPENAI_") or line.startswith("ANTHROPIC_") or line.startswith("AGENTTRUST_"):
                var_name = line.split(":", 1)[0].split("=")[0].strip()
                if var_name:
                    env_var_names.append(var_name)

        ext_ref = f"cicd:{pipeline_name}"
        return [
            DiscoveredResource(
                external_reference=ext_ref,
                candidate_type="PIPELINE",
                display_name=pipeline_name,
                environment=environment,
                location_reference=f"pipeline://{pipeline_name}",
                dependencies=sorted(list(set(dependencies))),
                env_var_names=sorted(list(set(env_var_names))),
                relationships=[
                    {
                        "type": "DEPLOYED_BY_PIPELINE",
                        "target": pipeline_name,
                        "confidence": "VERIFIED",
                    }
                ],
                raw_metadata={"platform": self.config.get("platform", "GITHUB_ACTIONS")},
            )
        ]
