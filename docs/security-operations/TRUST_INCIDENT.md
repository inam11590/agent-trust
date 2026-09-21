# Incident Runbook: Cross-Organization Trust Violations

## Alert Identifier
- ule_trust_violation: Repeated trust verification failure (HIGH).

## Symptoms
An external Agent from Organization B attempted to call protected resources in Organization A without valid active trust.

## Investigation Steps
1. **Identify Peer Organization**:
   - Check the partner_organization_id in the event metadata.
2. **Review Trust Agreement**:
   - Inspect /dashboard/trust to check if an agreement between the two organizations existed previously.
   - Verify if the agreement was REVOKED, EXPIRED, or REJECTED.
3. **Inspect Delegation Chain**:
   - Check if an agent attempted an out-of-scope delegation hop beyond the permitted trust depth.
4. **Action**:
   - If accidental misconfiguration: Contact partner organization administrators.
   - If unauthorized probe: Ensure the authorization policy continues to block calls (decision: DENIED).
5. **Resolution**:
   - Resolve alert once the partner stops unauthorized calls or an updated trust agreement is established.
