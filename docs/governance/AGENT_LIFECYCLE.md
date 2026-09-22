# Agent Lifecycle State Machine (Step 28)

## 1. Overview

AgentTrust provides a deterministic, centralized lifecycle state machine for AI agents. Rather than treating agents as static credentials or database records, enterprise governance treats agents as living software identities that progress through defined lifecycle states with separation-of-duties enforcement and cryptographic verification.

---

## 2. Lifecycle State Definitions

| State | Scope & Permissions | Description |
|---|---|---|
| `DRAFT` | No runtime execution | Initial registration or authoring stage. Metadata and declared capabilities can be iteratively configured. |
| `REGISTERED` | Sandbox / Dev only | Agent identity is registered, public keys may be bound, but formal security approval is pending. |
| `REVIEW_REQUIRED` | Blocked for production | Promotion submitted. The agent is in the compliance & security review queue. |
| `APPROVED` | Ready for activation | Security reviewer or team lead has validated the checklist and approved the agent. |
| `ACTIVE` | Fully operational | Agent is authorized to sign actions, present credentials, and process delegated tasks within policy limits. |
| `SUSPENDED` | **Fail-Closed Rejection** | Agent is temporarily frozen due to policy violations, overdue reviews, or incident response. Rejected with `AGENT_SUSPENDED`. |
| `RETIREMENT_PENDING` | Grace period | Decommissioning initiated. Dependent agents and callers are notified to migrate off. |
| `RETIRED` | **Permanent Terminal** | Decommissioned identity. All credentials revoked, delegations severed, keys disabled. Rejection code `AGENT_RETIRED`. Audit records permanently preserved. |

---

## 3. Transition Matrix

```
       [Creation] ---> DRAFT ---> REGISTERED ---> REVIEW_REQUIRED ---> APPROVED ---> ACTIVE <---+
                         |            |                 |                |            |         | (Reactivate)
                         |            |                 v                v            v         |
                         +------------+------------> REJECTED         CANCELLED    SUSPENDED ---+
                                                                                      |
                                                                                      v
                                                                             RETIREMENT_PENDING
                                                                                      | (Dependency Check)
                                                                                      v
                                                                                   RETIRED
```

### Transition Rules

1. **`DRAFT` -> `REGISTERED`**:
   - Allowed by: Agent Author, Developer, Admin.
   - Validation: Unique `agent_identifier`, valid name, assigned owner.

2. **`REGISTERED` -> `REVIEW_REQUIRED`**:
   - Allowed by: Agent Owner, Admin.
   - Validation: Enforces the Promotion Checklist (purpose, risk classification, data classification).

3. **`REVIEW_REQUIRED` -> `APPROVED`**:
   - Allowed by: Designated Reviewer, Organization Admin.
   - **Separation of Duties Invariant**: If `enforce_separation_of_duties` is active, the agent's owner cannot approve their own agent's promotion.

4. **`APPROVED` -> `ACTIVE`**:
   - Allowed by: Admin, Deployer.
   - Validation: Sets the certification validity window (`certified_until` = now + `periodic_review_days`).

5. **`ACTIVE` -> `SUSPENDED`**:
   - Allowed by: Any Admin, Security Lead, automated SOC detection.
   - Behavior: Immediate fail-closed propagation to Control Plane, Enterprise Gateways, and Sidecars.

6. **`SUSPENDED` -> `ACTIVE`**:
   - Allowed by: Admin, Security Lead with documented justification.

7. **`*` -> `RETIRED`**:
   - Allowed by: Admin, Owner.
   - Pre-flight Dependency Check executed. Active delegations severed and credentials revoked.

---

## 4. Promotion Checklist

Before an agent can be submitted to `REVIEW_REQUIRED` or approved into `ACTIVE`, the automated checklist validates:
- **Name**: Must be at least 3 characters.
- **Primary Owner**: Must have a valid owner ID and owner type (`USER`, `TEAM`, `SERVICE_OWNER`).
- **Business Purpose**: Description of business objectives and operational boundaries (minimum 10 characters).
- **Risk Classification**: Explicit designation of `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
- **Data Classification**: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, or `RESTRICTED`.
- **Expected Actions**: Declared API/tool action scopes.

---

## 5. Security & Gate Enforcement

When an agent enters `SUSPENDED` or `RETIRED`:
1. **Central Authorization**: In `backend/app/services/authorization.py`, all authorization requests immediately return `REJECTED` with error code `AGENT_SUSPENDED` or `AGENT_RETIRED`. No APL/1.0 policy or delegation bypass can override this.
2. **Gateway Distribution**: The agent identifier is added to `GatewayConfigBundle.revocations`. Gateways compile and sign a monotonically incremented bundle.
3. **Edge / Sidecar Enforcement**: Local Sidecars inspect the cached revocations list and fail closed before executing local policy evaluation.
