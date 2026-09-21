# Incident Runbook: Credential Security Incidents

## Alert Identifiers
- ule_revoked_cred_use: Attempt to authenticate using an explicitly revoked credential (HIGH).
- ule_compromised_key_use: Request verified with a key marked COMPROMISED (CRITICAL).

## Symptoms
Incoming API or ATP requests attempting to perform actions with invalid, revoked, or compromised credentials.

## Immediate Containment Actions
1. **Verify Denial**:
   - Confirm that the AgentTrust authorization engine immediately blocked the action (decision: DENIED).
2. **Quarantine Subject Agent**:
   - If a compromised key was presented, ensure all other keys associated with the Agent are placed in REVOKED state.
   - Transition the Agent status to QUARANTINED to prevent any further authorized calls.
3. **Trace Blast Radius**:
   - Query all events matching the credential_id or key_id over the preceding 7 days using the Event Explorer.
   - Identify any actions allowed prior to the revocation timestamp.
   - Notify downstream services that processed actions under the compromised credential.
4. **Audit Revocation List Propagation**:
   - Ensure the Trust Registry and Enterprise Gateways have pulled the latest revocation list (CRL / OCSP equivalent).
5. **Resolution**:
   - Issue a new credential with rotated key pairs to the verified agent operator.
   - Record incident resolution notes in the alert details.
