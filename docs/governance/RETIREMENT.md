# Safe Agent Decommissioning & Retirement Workflow (Step 28)

## 1. Overview

Retiring an autonomous AI agent in production requires rigorous dependency validation and credential teardown to prevent orphan calls, security loopholes, or broken downstream workflows.

---

## 2. Pre-flight Dependency Analysis

Before an agent is retired, AgentTrust performs a comprehensive pre-flight dependency check:
1. **Incoming Delegations**: Other agents that have delegated actions or authority to this agent.
2. **Outgoing Delegations**: Authorities this agent has delegated downstream to child agents.
3. **Active Verifiable Credentials (ATC/1.0)**: Issued cryptographic credentials that remain unexpired.
4. **Gateway & Policy Bindings**: Active routing and governance attachments.

If active dependencies exist, standard retirement requests are halted with status `409 Conflict` and a detailed dependency breakdown, unless `force=True` is provided.

---

## 3. Decommissioning Protocol

When retirement executes:
1. **Revoke Credentials**: All active credentials issued to the agent are transitioned to `REVOKED` with revocation reason `AGENT_RETIRED`.
2. **Terminate Delegations**: All active incoming and outgoing delegations are terminated (`status = REVOKED`).
3. **Deactivate Keys**: Associated agent signing keys are marked inactive/revoked.
4. **Transition State**: The agent status is atomically updated to `RETIRED`.
5. **Fail-Closed Enforcement**: All subsequent authorization attempts instantly reject with `AGENT_RETIRED`.
6. **Audit Preservation Invariant**: Historical audit logs, security events, and past authorization decisions are **never** hard-deleted. They remain permanently accessible for regulatory and forensic compliance.
