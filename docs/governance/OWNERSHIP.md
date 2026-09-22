# Accountable Agent Ownership & Transfer (Step 28)

## 1. Overview

AgentTrust mandates clear, accountable human and organizational ownership for every registered AI agent. Unowned or untracked software identities represent severe operational and compliance risks.

---

## 2. Ownership Models

Every agent possesses an `owner_type`:
1. `USER`: Directly assigned to a specific human user (e.g. lead developer or prompt engineer).
2. `TEAM`: Assigned to an engineering team or business group (e.g. `DataEngineering`, `CustomerOps`).
3. `SERVICE_OWNER`: Assigned to an enterprise service principal or machine identity.

Additionally, agents can have an assigned `team` string, establishing organizational alignment and cost attribution.

---

## 3. Ownership Transfer Workflow

When team responsibilities change, ownership must be formally transferred rather than deleted and recreated:

1. **Atomic Transfer**:
   - Updates `agent.owner_type`, `agent.owner_id`, and optionally `agent.team`.
   - Generates an immutable audit record in `agent_ownership_history`.
   - Dispatches a `SecurityEvent` with event type `agent_ownership_transferred`.

2. **Audit Record Structure (`agent_ownership_history`)**:
   - `id`: Unique record UUID.
   - `agent_id`: The affected agent.
   - `old_owner_type` / `old_owner_id`: Previous accountable owner.
   - `new_owner_type` / `new_owner_id`: Newly assigned accountable owner.
   - `changed_by`: Admin or user performing the change.
   - `reason`: Mandatory business justification.
   - `changed_at`: Canonical UTC timestamp.

---

## 4. Orphaned Agent Detection

The governance engine continuously monitors for orphaned identities:
- **`OWNER_MISSING`**: Agent has null `owner_id` or owner record cannot be resolved in the database.
- **`OWNER_DISABLED`**: The user account owning the agent is deactivated, removed, or no longer an active member of the organization.

Orphaned agents are flagged on the Executive Governance Dashboard and highlighted in the hygiene signals queue.
