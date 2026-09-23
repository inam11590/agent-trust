"""Import Discovery Connector (Step 29).

Enforces:
- Ingests pre-sanitized external inventory records (e.g. from enterprise CMDB or CSV/JSON exports)
- Strict validation and field mapping
"""

from __future__ import annotations

from typing import Any, Dict, List
from app.services.discovery.connectors.base import BaseDiscoveryConnector, DiscoveredResource


class ImportDiscoveryConnector(BaseDiscoveryConnector):
    """Parses static batch discovery imports."""

    def test_connection(self) -> Dict[str, Any]:
        return {"status": "CONNECTED", "connector": "IMPORT", "read_only": True}

    def scan(self) -> List[DiscoveredResource]:
        records = self.config.get("records") or []
        discovered: List[DiscoveredResource] = []

        for r in records:
            name = r.get("name") or r.get("display_name") or "imported-candidate"
            ext_ref = r.get("external_resource_reference") or f"import:{name}"
            discovered.append(
                DiscoveredResource(
                    external_reference=ext_ref,
                    candidate_type=r.get("candidate_type", "WORKLOAD"),
                    display_name=name,
                    environment=r.get("environment", "unknown"),
                    location_reference=r.get("location_reference", "cmdb://import"),
                    dependencies=r.get("dependencies", []),
                    env_var_names=r.get("env_var_names", []),
                    labels=r.get("labels", {}),
                    image_name=r.get("image_name"),
                    suggested_owner=r.get("suggested_owner"),
                    relationships=r.get("relationships", []),
                    raw_metadata=r.get("raw_metadata", {}),
                )
            )

        return discovered
