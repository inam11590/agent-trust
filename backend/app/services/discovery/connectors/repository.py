"""Source Repository Discovery Connector (Step 29).

Enforces:
- Pure text and manifest parsing
- Zero execution of repository code
- Zero execution of install/setup/build scripts
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from app.services.discovery.connectors.base import BaseDiscoveryConnector, DiscoveredResource


class SourceRepositoryDiscoveryConnector(BaseDiscoveryConnector):
    """Inspects source code repository manifests for AI agent and model dependencies."""

    def test_connection(self) -> Dict[str, Any]:
        repo_url = self.config.get("repository_url", "https://github.com/org/repo")
        return {
            "status": "CONNECTED",
            "repository": repo_url,
            "read_only": True,
            "code_execution": False,
        }

    def scan(self) -> List[DiscoveredResource]:
        repo_name = self.config.get("repo_name", "enterprise-repo")
        manifests = self.config.get("manifests") or {}
        codeowners = self.config.get("codeowners", "")
        environment = self.config.get("environment", "development")

        dependencies: List[str] = []
        env_var_names: List[str] = []

        # 1. Parse requirements.txt
        if "requirements.txt" in manifests:
            content = manifests["requirements.txt"]
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    pkg = re.split(r"[=><~;]", line)[0].strip()
                    if pkg:
                        dependencies.append(pkg)

        # 2. Parse package.json
        if "package.json" in manifests:
            try:
                pkg_data = json.loads(manifests["package.json"])
                deps = pkg_data.get("dependencies", {})
                dev_deps = pkg_data.get("devDependencies", {})
                dependencies.extend(list(deps.keys()))
                dependencies.extend(list(dev_deps.keys()))
            except Exception:
                pass

        # 3. Parse Dockerfile (search for ENV statements safely)
        if "Dockerfile" in manifests:
            docker_content = manifests["Dockerfile"]
            for line in docker_content.splitlines():
                line = line.strip()
                if line.startswith("ENV "):
                    tokens = line[4:].strip().split()
                    for t in tokens:
                        var_name = t.split("=")[0].strip()
                        if var_name:
                            env_var_names.append(var_name)

        # Suggested owner from CODEOWNERS
        suggested_owner = None
        if codeowners:
            # e.g. "* @core-ai-team"
            first_line = codeowners.strip().splitlines()[0]
            owner_token = first_line.split()[-1].lstrip("@")
            suggested_owner = {
                "owner_name": owner_token,
                "owner_type": "TEAM",
                "confidence": "HIGH",
                "reasons": ["Extracted from repository CODEOWNERS configuration"],
            }

        ext_ref = f"repo:{repo_name}"
        resource = DiscoveredResource(
            external_reference=ext_ref,
            candidate_type="REPOSITORY",
            display_name=repo_name,
            environment=environment,
            location_reference=f"git://{repo_name}",
            dependencies=sorted(list(set(dependencies))),
            env_var_names=sorted(list(set(env_var_names))),
            suggested_owner=suggested_owner,
            relationships=[
                {
                    "type": "DEFINED_IN_REPOSITORY",
                    "target": repo_name,
                    "confidence": "VERIFIED",
                }
            ],
            raw_metadata={"scanned_files": list(manifests.keys())},
        )

        return [resource]
