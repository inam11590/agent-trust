# AgentTrust Policy Language (APL/1.0) Security Architecture

## 1. Threat Model & Sandboxing Guarantees

In AI agent architectures, malicious or compromised agents may attempt to trick, bypass, or exhaust policy enforcement engines. APL/1.0 eliminates these attack vectors by design.

### Threat Mitigations:
1. **Remote Code Execution (RCE):** Policies are parsed with strict safe-loaders into structured AST nodes. No code generator or interpreter runtime (Python, JS, shell, eval, exec) is used.
2. **Denial of Service (DoS & ReDoS):** All policy documents are strictly bounded by size (64KB), rule count (50), condition count (20), and nesting (depth 4). Regular expressions are prohibited; only literal prefix/suffix checks are executed.
3. **Type Confusion & Coercion Exploits:** Type comparison is strongly enforced. A string value `"500"` will not silently match a numeric boundary `500`.
4. **Missing Field Vulnerabilities:** Comparison operators evaluate to `False` if a required comparison field is missing or null, preventing inadvertent approval bypass.
5. **State & Side-Effect Isolation:** Policy evaluation is pure and stateless. Simulators and impact analysis run without side effects (no database writes, no charges, no live approvals).

---

## 2. Invariant Hierarchy

APL/1.0 operates as an authorization refinement engine. It can **only restrict authority**, never expand it beyond platform bounds.

```
+-------------------------------------------------------------+
| PLATFORM SECURITY INVARIANTS (Non-overridable, Fail-Closed) |
| - Ed25519 Request Signature Verification                    |
| - Anti-Replay Nonce & Clock Skew Validation (300s window)   |
| - Agent Cryptographic Key Status (Active / Not Revoked)      |
| - Target Endpoint SSRF & IP Validation                       |
| - Mandatory Cross-Organization Trust Status                  |
| - Verifiable Credential Validity (ATC/1.0 Not Revoked)      |
+-------------------------------------------------------------+
                              | (Must Pass)
                              v
+-------------------------------------------------------------+
| AGENT PERMISSION BOUNDS                                     |
| - Action Allowed in Agent Capability Manifest               |
| - Temporal Scope & Resource Scope Validated                 |
+-------------------------------------------------------------+
                              | (Must Pass)
                              v
+-------------------------------------------------------------+
| APL/1.0 POLICY-AS-CODE RULES                                |
| - Organizational Rules & Tiered Approval Limits             |
| - Environment Restrictions (Prod vs Sandbox)                |
| - Final Decision: DENY > REQUIRE_APPROVAL > ALLOW           |
+-------------------------------------------------------------+
```

---

## 3. Cryptographic Distribution to Enterprise Gateways

1. **Signed Config Bundles:** Published policies are compiled into canonical JSON ASTs, hashed with SHA-256 (`content_hash`), and embedded into signed configuration snapshots signed by the Control Plane's Ed25519 key (`AGENTTRUST-CONFIG/1`).
2. **Monotonic Versioning:** Every policy rollback or update increments the configuration snapshot version monotonically. Gateways reject stale or lower-version configurations.
3. **Independent Local Enforcement:** Enterprise Gateways and Sidecars evaluate the identical APL/1.0 compiled AST locally in the Data Plane without sending confidential prompts or payloads to the Control Plane.
