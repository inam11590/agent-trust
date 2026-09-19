# AgentTrust Credential Security Threat Model (ATC/1.0)

This document analyzes threat vectors, attack surfaces, and mitigation strategies for AgentTrust Verifiable Agent Credentials (`ATC/1.0`).

---

## 1. Threat Matrix

| Threat Category | Description | Primary Mitigation |
| :--- | :--- | :--- |
| **Credential Forgery** | Attacker fabricates a credential out of whole cloth claiming authority. | Ed25519 asymmetric cryptographic signing by registered issuer identity keys. Verifiers inspect public keys published in the Trust Registry. |
| **Credential Tampering** | Attacker takes a valid credential and alters claims (e.g., escalating capability from `hotel.search` to `hotel.reserve`). | Canonical ASCII binding (`ATC-SIG/1`) includes `claims_sha256`. Any modification causes signature check failure (`CREDENTIAL_SIGNATURE_INVALID`). |
| **Credential Copying & Replay** | Attacker intercepts a public credential and re-presents it from an unauthorized agent. | **Credential possession is not authentication.** Requests must be signed by the agent's active Ed25519 key with nonce and timestamp. Gateway enforces `subject.agent_id == source_agent.id`. |
| **Subject Impersonation** | Agent A presents a credential issued to Agent B. | Verification engine checks subject binding against the authenticated requesting agent. |
| **Organization Swapping** | Rogue agent presents a credential issued by Org A while claiming to represent Org B. | Organization binding: verifier checks that `subject.organization_id` matches the authenticated source organization context. |
| **Stale Revocation Abuse** | Attacker uses a revoked credential before verifiers learn of revocation. | Gateway performs authoritative synchronous lookup on credential status; client SDKs enforce strict short TTLs (<60s) on cached statuses. |
| **Capability Inflation** | Issuer claims capabilities for an agent that were never registered. | Issuance engine validates that requested capabilities exist in the organization's published capability catalog. |
| **Sandbox Crossing** | Attacker presents a test/sandbox credential to a production gateway. | `environment` is explicitly signed in the canonical string; production gateway rejects `environment == "sandbox"` credentials. |
| **Issuer Key Compromise** | An issuer's signing key is compromised. | Key rotation and revocation primitives; revoking the key immediately invalidates all credentials signed with it. |
| **Authorization Bypass Attempt** | Attacker assumes having a valid credential bypasses permission checks. | **Core rule:** Credential verification is prerequisite to, but never substitutes for, permission, trust, policy, and human approvals. |

---

## 2. Privacy Controls

Credentials follow the principle of data minimization:
- **Public Claims Only**: Contain only agent identifier, organization identifier, validity window, and capability strings.
- **No Sensitive Corporate Data**: No PII, employee names, financial balances, billing tokens, internal policy rules, or private audit traces are permitted in credential claims.
