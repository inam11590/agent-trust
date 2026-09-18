# Cross-Organization Threat Model & Security Analysis

## 1. Scope and Assumptions

This threat model analyzes the security boundaries and attack vectors associated with **Cross-Organization Agent-to-Agent Trust** in AgentTrust.

### Security Boundaries
1. **Tenant Isolation**: Data, cryptographic keys, internal policies, team members, and audit logs of Organization A must remain strictly confidential and invisible to Organization B.
2. **Cryptographic Agent Attestation**: All requests executed by an agent must be signed locally on the developer machine using an Ed25519 private key. Private keys are never uploaded or transmitted to the server.
3. **Immutability of Audit Trails**: Decisions, signatures, nonces, and approval events are recorded in append-only logs.

---

## 2. Threat Scenarios and Mitigations

### Threat 1: Confused Deputy Attack
* **Scenario**: An attacker prompts Agent A (belonging to Org A) to invoke Agent B (belonging to Org B) to perform an unauthorized privileged action, attempting to trick Agent B into acting on behalf of Agent A without authorization.
* **Mitigation**:
  - The v2 signature binds `source_org_id`, `target_org_id`, `source_agent_id`, `target_agent_id`, `action`, `resource`, and request body.
  - Step 5 of the evaluation verifies that Source Agent A has explicit internal permissions for the requested action/resource.
  - Step 6 verifies that Org A has an active directional trust relationship with Org B.
  - Step 7 verifies that an explicit External Agent Connection connects Agent A to Agent B.
  - An agent cannot act as an open proxy or claim authority it does not possess.

### Threat 2: Signature Replay & Cross-Endpoint Substitution
* **Scenario**: An attacker intercepts a signed cross-org authorization request and attempts to replay it to another endpoint, or send the same request to a different target agent or organization.
* **Mitigation**:
  - The v2 canonical signature explicitly binds both `method`, `path`, `source_org_id`, `target_org_id`, `source_agent_id`, and `target_agent_id`.
  - An intercepted signature cannot be substituted for any other target agent, organization, or path.
  - Replay attacks are prevented using an atomic distributed nonce store (Redis / PostgreSQL unique constraint) within a strict 5-minute validity window (`AGENT_SIGNATURE_CLOCK_WINDOW_SECONDS = 300`).

### Threat 3: Policy Laundering & Constraint Relaxation
* **Scenario**: Org A proposes a spending cap of $500. Org B’s policy allows $200. An attacker attempts to exploit differences in policies to execute a $400 transaction.
* **Mitigation**:
  - AgentTrust enforces **"Strongest Restriction Always Wins"**.
  - The effective limit is computed as $\min(\text{Source Max}, \text{Agreed Trust Max}, \text{Target Max})$. In this scenario, the effective maximum is $200. Any transaction above $200 is automatically rejected.
  - Strictest approval requirement always dominates (`BOTH` overrides `SOURCE` or `TARGET`).

### Threat 4: Cross-Tenant Data Leakage in Audit Logs
* **Scenario**: An organization views audit logs to inspect the internal risk assessments, security events, or team members of its partner organization.
* **Mitigation**:
  - Audit logs are decoupled at the database level.
  - Source organization receives only outbound audit logs containing: partner organization ID, target agent public identifier, action, resource, amount, decision, and outbound reason.
  - Target organization receives only inbound audit logs containing: partner organization ID, source agent public identifier, action, resource, amount, decision, and inbound reason.
  - Neither organization can access the partner's internal risk scores, risk reasons, internal user IDs, or private policies.

### Threat 5: Revocation Race Conditions
* **Scenario**: Org B revokes trust with Org A, but Org A attempts to rush through queued or in-flight requests.
* **Mitigation**:
  - Trust revocation takes effect atomically and immediately in PostgreSQL.
  - Every authorization request evaluates trust status in real time (`trust.status == TrustStatus.ACTIVE`).
  - Pending multi-party requests tied to a revoked trust relationship are invalidated and rejected immediately upon decision.

---

## 3. Residual Risk & Recommendations

1. **Private Key Storage**: Developers must safeguard local Ed25519 private keys using appropriate file permissions (0600) and HSMs/vaults in production.
2. **Clock Drift**: Servers and developer systems must maintain NTP synchronization to ensure request timestamps remain within the 300-second window. Run `agenttrust doctor` to verify clock drift.
