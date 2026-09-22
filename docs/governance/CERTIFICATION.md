# Agent Certification & Periodic Access Review (Step 28)

## 1. Overview

Autonomous agents accumulate permissions, credentials, delegations, and policy exceptions over time. To maintain compliance (SOC 2, ISO 27001, FedRAMP), AgentTrust provides an automated, periodic access certification engine.

---

## 2. Point-in-Time Posture Snapshots

When a certification review is initiated, the engine captures an immutable point-in-time snapshot of the agent's complete posture:
- **Identity & Owner**: Name, identifier, owner, team, purpose.
- **Permissions**: Granted actions, target resources, monetary limits, conditions.
- **Verifiable Credentials (ATC/1.0)**: Issued credential IDs, types, issuers, expiration dates.
- **Delegations**: Active incoming and outgoing delegation chains.
- **Policy Bindings**: Bound declarative policies (APL/1.0) and priority order.

This snapshot is stored in `agent_certifications.snapshot_reference` and displayed to reviewers during evaluation.

---

## 3. Periodic Review Lifecycle

1. **Initiation**:
   - Reviews can be scheduled automatically every `periodic_review_days` (default: 90 days), or manually triggered via UI, API, or CLI.
   - Status is set to `PENDING`, and agent's `certification_status` is updated to `REVIEW_DUE`.

2. **Evaluation & Decision**:
   - Reviewer inspects the captured posture snapshot.
   - Decision must be `APPROVED` or `REJECTED` with rationale.
   - **Separation of Duties**: Agent owner cannot approve their own agent's review when enabled in organization governance policy.

3. **Approval Effects**:
   - `last_reviewed_at` updated to current UTC time.
   - `certified_until` extended to `now + periodic_review_days`.
   - `certification_status` set to `CERTIFIED`.

4. **Rejection / Expiry Effects**:
   - Governed by `AgentGovernancePolicy.expiry_behavior`:
     - `ALERT_ONLY`: Emits warning signal, agent remains active.
     - `REVIEW_REQUIRED`: Agent transitions to `REVIEW_REQUIRED` state.
     - `SUSPEND`: Agent is immediately suspended with fail-closed enforcement.
