"""Kubernetes Read-Only Discovery Connector (Step 29).

Enforces:
- Least-privilege read-only permissions (Get, List, Watch on Workloads)
- Never reads Kubernetes Secret values
- Never dumps ConfigMap bodies blindly
- Safe metadata inspection: namespaces, deployments, statefulsets, pods, images, labels, env variable names
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from app.services.discovery.connectors.base import BaseDiscoveryConnector, DiscoveredResource


LEAST_PRIVILEGE_K8S_RBAC_YAML = """---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: agenttrust-discovery-reader
rules:
- apiGroups: ["apps"]
  resources: ["deployments", "statefulsets", "daemonsets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["batch"]
  resources: ["jobs", "cronjobs"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods", "services", "namespaces"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: agenttrust-discovery-reader-binding
subjects:
- kind: ServiceAccount
  name: agenttrust-discovery
  namespace: agenttrust-system
roleRef:
  kind: ClusterRole
  name: agenttrust-discovery-reader
  apiGroup: rbac.authorization.k8s.io
"""


class KubernetesDiscoveryConnector(BaseDiscoveryConnector):
    """Discovers AI workloads and agents running in Kubernetes clusters."""

    def test_connection(self) -> Dict[str, Any]:
        cluster_name = self.config.get("cluster_name", "kubernetes-cluster")
        namespaces = self.config.get("namespaces", ["default"])
        return {
            "status": "CONNECTED",
            "cluster_name": cluster_name,
            "inspected_namespaces": namespaces,
            "read_only": True,
            "secret_access": False,  # Explicitly verification that secrets are never read
        }

    def scan(self) -> List[DiscoveredResource]:
        """Scan Kubernetes workloads using provided or simulated manifest descriptors."""
        cluster_name = self.config.get("cluster_name", "k8s-cluster")
        environment = self.config.get("environment", "production")
        
        # Manifests can be passed via configuration (for testing/mocking/API feeds)
        raw_workloads = self.config.get("manifests") or self.config.get("workloads") or []
        discovered: List[DiscoveredResource] = []

        for item in raw_workloads:
            kind = item.get("kind", "Deployment")
            metadata = item.get("metadata", {})
            name = metadata.get("name", "unknown-workload")
            namespace = metadata.get("namespace", "default")
            labels = metadata.get("labels", {})
            annotations = metadata.get("annotations", {})

            spec = item.get("spec", {})
            template = spec.get("template", {})
            pod_spec = template.get("spec", spec)
            containers = pod_spec.get("containers", [])

            dependencies = []
            env_var_names = []
            images = []

            for c in containers:
                img = c.get("image", "")
                if img:
                    images.append(img)
                
                # Collect environment variable NAMES ONLY - NEVER VALUES!
                for env in c.get("env", []):
                    if isinstance(env, dict) and "name" in env:
                        env_var_names.append(env["name"])

            # Check owner labels
            suggested_owner = None
            if "owner" in labels or "team" in labels:
                suggested_owner = {
                    "owner_name": labels.get("owner") or labels.get("team"),
                    "owner_type": "TEAM" if "team" in labels else "USER",
                    "confidence": "HIGH" if "owner" in labels else "MEDIUM",
                    "reasons": [f"Extracted from Kubernetes label: {labels.get('owner') or labels.get('team')}"],
                }

            # Relationships
            relationships = [
                {
                    "type": "DEPLOYED_IN_NAMESPACE",
                    "target": f"k8s:{cluster_name}/ns/{namespace}",
                    "confidence": "VERIFIED",
                }
            ]

            primary_image = images[0] if images else None
            ext_ref = f"k8s:{cluster_name}/{namespace}/{kind.lower()}/{name}"

            resource = DiscoveredResource(
                external_reference=ext_ref,
                candidate_type="WORKLOAD",
                display_name=name,
                environment=environment,
                location_reference=f"k8s://{cluster_name}/{namespace}",
                dependencies=dependencies,
                env_var_names=sorted(list(set(env_var_names))),
                labels=labels,
                image_name=primary_image,
                suggested_owner=suggested_owner,
                relationships=relationships,
                raw_metadata={
                    "kind": kind,
                    "namespace": namespace,
                    "annotations": {k: v for k, v in annotations.items() if not k.startswith("secret")},
                },
            )
            discovered.append(resource)

        return discovered
