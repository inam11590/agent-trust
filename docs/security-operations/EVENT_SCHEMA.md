# AgentTrust Unified Security Event Schema

Schema Version: genttrust.security.event/v1

## Overview
The AgentTrust Enterprise Security Operations Center (SOC) uses a unified, normalized security event model. Every critical security, authorization, credential, replay, and gateway action emits a structured SecurityEvent record.

All security events are immutable, append-only, tenant-isolated, and strictly scrubbed of private keys, passwords, and raw business payloads.

---

## Standard Event Fields

| Field Name | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| event_id | String | Globally collision-safe event identifier | evt_01HXYZ7890ABCDEF12345678 |
| organization_id | UUID | Authenticated organization context (multi-tenant boundary) | 8f2c3b4a-1122-3344-5566-778899aabbcc |
| event_type | String | Specific event type identifier | gent_replay_detected |
| category | String | High-level security category | REPLAY |
| severity | String | Severity rating: INFO, LOW, MEDIUM, HIGH, CRITICAL | HIGH |
| 	imestamp | ISO-8601 UTC | UTC timestamp when the event occurred | 2026-09-21T15:30:00Z |
| source_type | String | Source subsystem (e.g., API, GATEWAY, SIDECAR, WORKER) | GATEWAY |
| source_id | String | Unique identifier of the emitting source | gw_enterprise_us_east_1 |
| gent_id | UUID / null | Associated AI Agent identifier, if applicable | 3d5f7a9c-... |
| gateway_id | UUID / null | Associated Enterprise Gateway identifier, if applicable | e4b2c1d0-... |
| credential_id | UUID / null | Associated ATC credential identifier, if applicable | 1b2c3d4-... |
| equest_id | String / null | HTTP / ATP request identifier | eq_987654321 |
| 	race_id | String / null | Distributed trace identifier (W3C / OpenTelemetry) | 	race_4bf92f3577b34da6a3ce929d0e0e4736 |
| correlation_id | String / null | End-to-end operation correlation identifier | corr_delegation_flow_42 |
| ctor_type | String | Type of initiating actor (USER, AGENT, GATEWAY, SYSTEM) | AGENT |
| ctor_id | String / null | Actor identifier | gt_travel_booking_v1 |
| 	arget_type | String / null | Target resource type (AGENT, CREDENTIAL, GATEWAY, POLICY) | CREDENTIAL |
| 	arget_id | String / null | Target resource identifier | cred_finance_read |
| ction | String | Action performed or attempted | erify_atc_credential |
| decision | String / null | Security decision (ALLOWED, DENIED, CHALLENGED) | DENIED |
| isk_level | String / null | Risk assessment score (LOW, MEDIUM, HIGH, CRITICAL) | HIGH |
| egion | String / null | Cloud / deployment region | us-east-1 |
| environment | String | Deployment environment (production, staging, development) | production |
| details | JSON Object | Safe metadata dictionary (strictly scrubbed of secrets/payloads) | {reason: NONCE_REUSED, nonce: abc123...} |
| created_at | ISO-8601 UTC | Internal database insertion timestamp | 2026-09-21T15:30:00.123Z |

---

## Event Categories

- AUTHENTICATION: User, Agent, and Gateway login and authentication flows.
- AUTHORIZATION: Authorization policy evaluations, permission checks, and decisions.
- AGENT: AI Agent lifecycle, status modifications, key registrations, and rotations.
- CREDENTIAL: ATC/1.0 credential issuance, verification, expiration, and revocations.
- TRUST: Cross-organization trust agreements, modifications, and revocations.
- DELEGATION: Agent-to-Agent delegation issuance, verification, and expiration.
- GATEWAY: Enterprise Gateway registrations, heartbeats, configuration pulls, and revocations.
- REPLAY: Nonce collisions, timestamp skews, and replay attack detections.
- POLICY: Organization security policy modifications, approval rule triggers.
- APPROVAL: Human-in-the-loop multi-party approval requests, decisions, and denials.
- ADMIN: Administrative configuration updates, role assignments, and MFA/SSO settings.
- SYSTEM: Internal subsystem lifecycle events, worker jobs, and health checks.
- RELIABILITY: Failover, multi-region synchronization, and circuit-breaker activations.
- SUPPLY_CHAIN: Dependency, container, or configuration integrity events.

---

## Severity Guidance

- INFO: Normal operational actions (successful logins, policy updates, agent registrations).
- LOW: Minor anomalies with low immediate risk (e.g. single expired token renewal attempt).
- MEDIUM: Suspicious actions or repeated failures (e.g. repeated MFA challenge failures, elevated risk decision).
- HIGH: Confirmed attack attempts or security violations (e.g. replay attack bursts, invalid cryptographic signatures, revoked credential usage, gateway auth failures).
- CRITICAL: Immediate compromise or platform-level threats (e.g. usage of a cryptographic key marked COMPROMISED, insecure production configuration attempt, configuration rollback attack).
