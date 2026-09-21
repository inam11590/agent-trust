# Incident Runbook: Enterprise Gateway Security Incidents

## Alert Identifiers
- ule_gateway_auth_failure: Repeated Gateway authentication failure (HIGH).
- ule_gateway_offline: Gateway heartbeat missing beyond threshold (HIGH).
- ule_config_rollback: Gateway configuration rollback detected (HIGH).

## Symptoms
Enterprise Gateway node is disconnected, presenting invalid credentials, or rejecting configuration updates.

## Investigation Steps
1. **Gateway Identity & Heartbeat**:
   - Inspect /dashboard/security/gateways/{id}.
   - Check last_seen_at and offline_age_seconds.
   - Verify network health between the Gateway cluster and the AgentTrust Control Plane.
2. **Config Version & Signature**:
   - If a rollback attempt was detected, check the Gateway's local cache.
   - Verify if an operator attempted to deploy an older configuration version or if an attacker attempted to forge the configuration signature.
   - Confirm that the Gateway rejected the stale configuration and stayed on the last valid signed version.
3. **Remediation**:
   - If a Gateway credential leaked, revoke the gateway in /dashboard/gateways.
   - Provision a new gateway bootstrap token and re-enroll the node.
4. **Resolution**:
   - Once the Gateway reconnects with valid signatures and current configuration, resolve the alert.
