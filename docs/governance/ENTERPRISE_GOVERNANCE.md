# Enterprise Agent Governance Architecture (Step 28)

## 1. Architectural Principles

The AgentTrust Enterprise Agent Lifecycle Governance system provides authoritative management of AI identities throughout their lifecycle.

```
+-------------------------------------------------------------------------------+
|                         Enterprise Governance Plane                           |
+-------------------------------------------------------------------------------+
| 1. Authoritative Inventory   - Rich metadata, purpose, and classification     |
| 2. Ownership Accountability  - Primary/team owners and transfer audit trails  |
| 3. Lifecycle State Machine   - Promotion checklist and state transitions       |
| 4. Periodic Access Reviews   - Point-in-time posture snapshots & decisions    |
| 5. Blast-Radius Analysis     - Topology graph and exposure index scoring       |
| 6. Emergency Suspension      - Fail-closed edge propagation via signed bundle  |
| 7. Safe Decommissioning      - Dependency teardown with audit preservation     |
+-------------------------------------------------------------------------------+
              |                                                 |
              v                                                 v
+----------------------------+                   +----------------------------+
|   Control Plane Decision   |                   |  Enterprise Gateway/Edge   |
|   - AGENT_SUSPENDED        |                   |  - Local Revocations Cache |
|   - AGENT_RETIRED          |                   |  - Zero Network Round-Trip |
+----------------------------+                   +----------------------------+
```

---

## 2. Governance Signals Engine

The platform continuously evaluates 9 enterprise governance hygiene signals:

| Signal Code | Trigger Condition | Recommended Action |
|---|---|---|
| `OWNER_MISSING` | Agent has no assigned human or service owner | Reassign primary owner immediately |
| `OWNER_DISABLED` | Owner user account is disabled or left organization | Execute ownership transfer workflow |
| `REVIEW_DUE` | Review window due within 14 days | Initiate periodic certification review |
| `REVIEW_OVERDUE` | Review due date has passed | Escalate to security team; enforce expiry policy |
| `CERTIFICATION_EXPIRED`| Certification validity window has lapsed | Re-certify or suspend agent |
| `AGENT_DORMANT` | No authorization activity for &gt; 90 days | Review need or move to retirement pending |
| `BROAD_PERMISSION` | Agent holds wildcard (`*`) action or resource | Scope permissions to least-privilege |
| `POSSIBLY_UNUSED_PERMISSION` | Granted permission with zero authorization calls | Revoke unused permission |
| `UNEXPECTED_PRODUCTION_ACCESS` | Non-production identity attempting prod resource | Block and alert SOC |

---

## 3. Blast-Radius & Dependency Topology

The relationship builder calculates an authoritative blast-radius exposure score based on:
- Connected upstream callers (`DELEGATES_TO`)
- Downstream authority targets (`DELEGATED_AUTHORITY_TO`)
- Active verifiable credentials (`HOLDS_CREDENTIAL`)
- Bound declarative policies (`GOVERNS_AGENT`)
- Base agent risk classification multiplier (`CRITICAL` x4, `HIGH` x2.5, `MEDIUM` x1.5, `LOW` x1.0)
