# AgentTrust Policy Deployment & Lifecycle Guide

This guide explains the safe 8-step lifecycle for deploying policies in AgentTrust:

---

## The 8-Step Lifecycle

```
1. Draft ➔ 2. Validate ➔ 3. Test ➔ 4. Simulate ➔ 5. Review ➔ 6. Publish ➔ 7. Gateways Sync ➔ 8. Rollback (if needed)
```

### 1. Draft
A developer creates a new draft version of a policy in YAML or JSON through the Web Dashboard, CLI, or API. Drafts can be edited freely and do not affect live traffic.

### 2. Validate
The system checks the policy against the APL/1.0 schema:
- Are all field names known?
- Are all operators valid for the field's data type?
- Are rule IDs unique?
- Does the document obey limits (max 64KB, max 50 rules, max 4 nesting depth)?

### 3. Test
Run the policy's unit test fixtures. For example:
- `$100` input should return `ALLOW`.
- `$750` input should return `REQUIRE_APPROVAL`.
- `$5,000` input should return `DENY`.

All tests must pass before the version can be submitted for review.

### 4. Simulate & Impact Analysis
- **Simulation**: Test what-if scenarios interactively without side effects.
- **Impact Analysis**: Compare the new policy against historical sanitized authorization contexts (for example, the last 7 days) to see how decisions would shift before going live.

### 5. Review & Approval (Separation of Duties)
Submit the policy for review. A Security Administrator reviews the semantic diff:
- Obvious authority expansions (e.g. limit increased from $500 to $10,000, or `DENY` changed to `ALLOW`) are clearly labeled **SECURITY-SENSITIVE CHANGE**.
- Separation of duties: in enterprise configurations, the policy creator cannot approve their own production policy.

### 6. Publish
Once approved, the policy version is published. Published versions are **100% immutable** and can never be modified. A permanent cryptographic SHA-256 hash is assigned.

### 7. Gateway Sync (Cryptographically Signed)
Publishing updates the authoritative configuration snapshot:
- The Control Plane compiles the policy into canonical JSON AST.
- A new monotonically incremented configuration version is generated and signed with the Control Plane's Ed25519 private key (`AGENTTRUST-CONFIG/1`).
- Enterprise Gateways and Sidecars verify the signature and evaluate the policy locally in the Data Plane.

### 8. Rollback (Safe Anti-Rollback)
If an issue occurs:
- Choose an earlier published policy version to restore.
- AgentTrust creates a **NEW, higher configuration version** referencing the previous policy.
- Old configuration numbers are never replayed, satisfying Step 23 anti-rollback security invariants.
