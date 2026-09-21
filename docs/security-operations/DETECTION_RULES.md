# Threat Detection Rules & Alert Engine

## Overview
AgentTrust includes a deterministic, declarative threat detection engine. The engine continuously evaluates incoming security events against configured detection rules to trigger actionable alerts without impacting real-time authorization performance.

To prevent remote code execution vulnerabilities, **detection rules are strictly declarative**. User-supplied code (Python, JavaScript, Shell, or SQL) is completely disallowed and rejected by the API.

---

## Built-In Detection Rules

| Rule ID | Name | Severity | Threshold | Time Window | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| ule_replay_burst | Replay Attack Burst | HIGH | 3 events | 300 seconds | Triggers when repeated nonce reuse or expired timestamp replay attempts are detected from the same Agent or source. |
| ule_invalid_sig_burst | Repeated Invalid Signatures | HIGH | 3 events | 300 seconds | Triggers when repeated cryptographic signature verification failures occur for an Agent. |
| ule_revoked_cred_use | Revoked Credential Usage | HIGH | 1 event | 60 seconds | Triggers immediately when a revoked ATC/1.0 credential is used to access resources. |
| ule_compromised_key_use | Compromised Key Usage | CRITICAL | 1 event | 60 seconds | Triggers immediately when any request attempts to verify with a cryptographic key marked COMPROMISED. |
| ule_trust_violation | Trust Relationship Violation | HIGH | 2 events | 300 seconds | Triggers when unauthorized cross-organization requests occur against expired or missing trust relationships. |
| ule_delegation_abuse | Delegation Chain Abuse | HIGH | 3 events | 300 seconds | Triggers when invalid, over-scoped, or revoked delegation chains are presented repeatedly. |
| ule_gateway_auth_failure | Gateway Authentication Failures | HIGH | 3 events | 300 seconds | Triggers when an Enterprise Gateway repeatedly fails mTLS or token authentication. |
| ule_gateway_offline | Gateway Unexpectedly Offline | HIGH | 1 event | Immediate | Triggers when an active Enterprise Gateway fails to report heartbeats beyond its maximum offline threshold. |
| ule_config_rollback | Gateway Config Rollback Attempt | HIGH | 1 event | Immediate | Triggers when a Gateway presents a stale or rolled-back configuration version number. |
| ule_admin_sec_change | Admin Security Configuration Change | MEDIUM | 1 event | Immediate | Triggers when organization security settings, MFA policy, or roles are modified. |
| ule_mfa_failure | Repeated MFA Challenge Failures | MEDIUM | 5 events | 300 seconds | Triggers when repeated MFA authentication attempts fail for a single user account. |
| ule_production_insecure_config | Insecure Production Configuration Attempt | CRITICAL | 1 event | Immediate | Triggers when an administrative action attempts to enable debug mode or disable TLS in production. |

---

## Alert Deduplication & Fingerprinting

To prevent notification fatigue during high-volume event storms (e.g. 5,000 replay attempts in 60 seconds), the engine deduplicates alerts:

1. A deterministic alert **fingerprint** is generated:
   ingerprint = sha256(organization_id + rule_id + (agent_id or gateway_id or target_id))
2. If an alert with this fingerprint is already in OPEN or ACKNOWLEDGED state within the active time window:
   - The existing alert's event_count is incremented.
   - The alert's last_seen_at is updated to the latest event timestamp.
   - A new alert is **not** created, avoiding duplicate notifications.
3. If no active alert exists or the prior alert was RESOLVED, a new SecurityAlert is opened.

---

## Alert Lifecycle

Alerts move through four standard lifecycle states:

`
+--------+       Acknowledge        +----------------+       Resolve        +------------+
|  OPEN  | -----------------------> |  ACKNOWLEDGED  | -------------------> |  RESOLVED  |
+--------+                          +----------------+                      +------------+
    |                                       |
    +--------------> INVESTIGATING <--------+
`

1. OPEN: Newly detected anomaly requiring triage.
2. ACKNOWLEDGED: A security analyst has claimed the alert and is actively reviewing the timeline.
3. INVESTIGATING: Complex incident under deep investigation; notes and related events are attached.
4. RESOLVED: Incident handled. Requires a mandatory or recommended resolution note explaining actions taken (e.g. Key revoked, agent quarantined).
