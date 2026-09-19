# AgentTrust Protocol (ATP/1.0) & Gateway Threat Model

## 1. Scope & Objective

This threat model assesses the security architecture, trust boundaries, and attack vectors of the AgentTrust Protocol (ATP/1.0) and AgentTrust Gateway.

---

## 2. Threat Scenarios & Countermeasures

| Threat | Description | Countermeasure in ATP/1.0 & Gateway |
| :--- | :--- | :--- |
| **Agent Impersonation** | An unauthorized entity claims to be `atp://org_skytravel/agt_travel`. | Requests must be signed with the agent's registered Ed25519 private key. Gateway verifies public key binding. |
| **Message Tampering** | An attacker intercepts an in-flight message and alters target, capability, or payload. | The canonical string for `ATP-SIG/1` binds message ID, source, target, capability, and SHA-256 payload digest. Any mutation invalidates the cryptographic signature. |
| **Replay Attacks** | An eavesdropper records a valid signed request and replays it later. | Timestamp freshness window ($\pm 300$ seconds) combined with an atomic distributed nonce store (Redis / PostgreSQL unique constraints). |
| **SSRF via Target Endpoints** | A malicious organization registers an agent endpoint pointing to `127.0.0.1`, internal AWS metadata (`169.254.169.254`), or private LAN subnets. | Mandatory SSRF filter blocks private IPv4/IPv6 ranges, loopbacks, link-local, and cloud metadata with pre-connection DNS validation. Endpoints require challenge-response verification before becoming `ACTIVE`. |
| **Confused Deputy** | An agent tricks another agent into executing actions outside of agreed bilateral trust limits. | The Gateway enforces 11-step authorization pipeline: source permissions, bilateral trust relationship, target inbound policies, and strongest-restriction arithmetic. |
| **Stale Authorization Reuse** | An attacker captures an authorized decision and attempts to reuse it indefinitely. | Gateway authorization attestations are strictly short-lived (60-second TTL) and tied to an immutable request ID. |
| **Cross-Tenant Leakage** | Organization A inspects Gateway responses or audit records to learn Organization B's internal risk rules, team members, or private policies. | Dual decoupled audit logs and scrubbed response envelopes ensure neither tenant receives internal policy definitions or secrets. |
| **Oversized Message DoS** | An adversary sends gigantic envelopes to exhaust Gateway memory or CPU. | Hard payload size limits (`atp_max_payload_bytes = 65536`) enforced at the HTTP boundary before parsing. |

---

## 3. Residual Risk & Deployment Advice

1. **Private Key Custody**: Agent private keys must stay on the developer/agent host. Never store private keys in source control or cloud logs.
2. **Gateway Key Rotation**: Gateway signing keys should be rotated periodically according to organization key management schedules.
