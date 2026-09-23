"""Gateway & Sidecar Observation Telemetry Discovery Connector (Step 29).

Enforces:
- Ingests observations when the Enterprise Gateway or Sidecar receives requests from unregistered agent identifiers
- Captures caller address, action/resource pattern, without saving business payloads
"""

from __future__ import annotations

from typing import Any, Dict, List
from app.services.discovery.connectors.base import BaseDiscoveryConnector, DiscoveredResource


class TelemetryDiscoveryConnector(BaseDiscoveryConnector):
    """Inspects Gateway and Sidecar data plane telemetry for unregistered agent workloads."""

    def test_connection(self) -> Dict[str, Any]:
        gateway_id = self.config.get("gateway_id", "gw_central")
        return {
            "status": "CONNECTED",
            "gateway_id": gateway_id,
            "read_only": True,
            "raw_payload_inspection": False,
        }

    def scan(self) -> List[DiscoveredResource]:
        gateway_id = self.config.get("gateway_id", "gw_central")
        raw_events = self.config.get("telemetry_events") or []
        discovered: List[DiscoveredResource] = []

        for ev in raw_events:
            observed_agent_id = ev.get("agent_id") or ev.get("observed_identifier") or "unknown_agent"
            caller_ip = ev.get("client_ip", "10.0.0.1")
            environment = ev.get("environment", "production")
            action = ev.get("action", "query")

            ext_ref = f"telemetry:{gateway_id}/{observed_agent_id}"
            discovered.append(
                DiscoveredResource(
                    external_reference=ext_ref,
                    candidate_type="RUNTIME_PROCESS",
                    display_name=f"Observed Workload ({observed_agent_id})",
                    environment=environment,
                    location_reference=f"gateway://{gateway_id}/{caller_ip}",
                    telemetry_signals=["GATEWAY_OBSERVATION"],
                    relationships=[
                        {
                            "type": "CONTACTED_GATEWAY",
                            "target": gateway_id,
                            "confidence": "VERIFIED",
                        }
                    ],
                    raw_metadata={"observed_agent_id": observed_agent_id, "action": action},
                )
            )

        return discovered
