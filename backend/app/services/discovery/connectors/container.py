"""Container Platform & Static Image Discovery Connector (Step 29).

Enforces:
- Static metadata analysis ONLY
- Zero container execution
- Zero arbitrary image pulling and running
"""

from __future__ import annotations

from typing import Any, Dict, List
from app.services.discovery.connectors.base import BaseDiscoveryConnector, DiscoveredResource


class ContainerPlatformDiscoveryConnector(BaseDiscoveryConnector):
    """Discovers AI services from Docker / Container runtime descriptions."""

    def test_connection(self) -> Dict[str, Any]:
        engine_name = self.config.get("engine", "docker-daemon")
        return {
            "status": "CONNECTED",
            "engine": engine_name,
            "read_only": True,
            "static_analysis_only": True,
        }

    def scan(self) -> List[DiscoveredResource]:
        raw_containers = self.config.get("containers") or []
        discovered: List[DiscoveredResource] = []
        platform_name = self.config.get("platform_name", "container-host-01")
        environment = self.config.get("environment", "production")

        for c in raw_containers:
            name = c.get("name", "unnamed-container")
            image = c.get("image", "")
            labels = c.get("labels", {})
            env_vars = c.get("env", [])
            
            # Safe env var names only
            env_var_names = []
            for ev in env_vars:
                if isinstance(ev, str) and "=" in ev:
                    env_var_names.append(ev.split("=", 1)[0].strip())
                elif isinstance(ev, dict) and "name" in ev:
                    env_var_names.append(ev["name"])

            suggested_owner = None
            if "maintainer" in labels or "team" in labels:
                suggested_owner = {
                    "owner_name": labels.get("maintainer") or labels.get("team"),
                    "owner_type": "TEAM" if "team" in labels else "USER",
                    "confidence": "MEDIUM",
                    "reasons": ["Extracted from container image label"],
                }

            ext_ref = f"container:{platform_name}/{name}"
            discovered.append(
                DiscoveredResource(
                    external_reference=ext_ref,
                    candidate_type="CONTAINER",
                    display_name=name,
                    environment=environment,
                    location_reference=f"docker://{platform_name}",
                    image_name=image,
                    labels=labels,
                    env_var_names=sorted(list(set(env_var_names))),
                    suggested_owner=suggested_owner,
                    relationships=[
                        {
                            "type": "RUNS_IMAGE",
                            "target": image,
                            "confidence": "VERIFIED",
                        }
                    ],
                    raw_metadata={"ports": c.get("ports", [])},
                )
            )

        return discovered
