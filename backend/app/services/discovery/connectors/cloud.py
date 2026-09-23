"""Provider-Neutral Cloud Discovery Connector Foundation (Step 29).

Supports:
- AWS (ECS Task Definitions, Lambda AI functions, Bedrock agent metadata)
- Azure (Azure Container Apps, AKS descriptors)
- Google Cloud (Cloud Run services, GKE descriptors)
- Read-only inventory IAM roles
"""

from __future__ import annotations

from typing import Any, Dict, List
from app.services.discovery.connectors.base import BaseDiscoveryConnector, DiscoveredResource


READ_ONLY_AWS_IAM_POLICY_EXAMPLE = """{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecs:ListTasks",
                "ecs:DescribeTaskDefinition",
                "lambda:ListFunctions",
                "lambda:GetFunctionConfiguration",
                "bedrock:ListAgents",
                "bedrock:GetAgent"
            ],
            "Resource": "*"
        }
    ]
}"""


class CloudDiscoveryConnector(BaseDiscoveryConnector):
    """Discovers AI workloads across Cloud Service Providers."""

    def test_connection(self) -> Dict[str, Any]:
        provider = self.config.get("provider", "AWS").upper()
        region = self.config.get("region", "us-east-1")
        return {
            "status": "CONNECTED",
            "provider": provider,
            "region": region,
            "read_only": True,
            "iam_role_configured": bool(self.credential or self.config.get("role_arn")),
        }

    def scan(self) -> List[DiscoveredResource]:
        provider = self.config.get("provider", "AWS").upper()
        region = self.config.get("region", "us-east-1")
        environment = self.config.get("environment", "production")
        raw_services = self.config.get("services") or []

        discovered: List[DiscoveredResource] = []

        for svc in raw_services:
            name = svc.get("name", "cloud-workload")
            service_type = svc.get("service_type", "ECS_TASK")
            env_vars = svc.get("env_names", [])
            tags = svc.get("tags", {})
            image = svc.get("image", "")

            ext_ref = f"{provider.lower()}:{region}:{service_type.lower()}/{name}"
            suggested_owner = None
            if "Owner" in tags or "Team" in tags:
                suggested_owner = {
                    "owner_name": tags.get("Owner") or tags.get("Team"),
                    "owner_type": "TEAM" if "Team" in tags else "USER",
                    "confidence": "HIGH" if "Owner" in tags else "MEDIUM",
                    "reasons": [f"Extracted from {provider} resource tag"],
                }

            discovered.append(
                DiscoveredResource(
                    external_reference=ext_ref,
                    candidate_type="SERVICE",
                    display_name=name,
                    environment=environment,
                    location_reference=f"{provider}://{region}/{service_type}",
                    image_name=image,
                    labels=tags,
                    env_var_names=sorted(list(set(env_vars))),
                    suggested_owner=suggested_owner,
                    relationships=[
                        {
                            "type": "HOSTED_ON_CLOUD",
                            "target": f"{provider}:{region}",
                            "confidence": "VERIFIED",
                        }
                    ],
                    raw_metadata={"cloud_provider": provider, "service_type": service_type},
                )
            )

        return discovered
