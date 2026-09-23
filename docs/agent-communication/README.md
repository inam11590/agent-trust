# AgentTrust Trusted Agent-to-Agent Communication & Service Registry

## Overview
Step 30 introduces enterprise-grade **Trusted Agent-to-Agent Communication** anchored by the **Agent Service Registry**. This system allows AI agents across services, teams, and organizations to discover capabilities and execute invocations with zero-trust security guarantees.

## Fundamental Architectural Invariants
1. **Service Discovery is NOT Trust**:
   Querying the Service Registry and resolving an endpoint returns candidate network routes, but **never authorizes execution**.
2. **Resolution Does NOT Authorize Action**:
   Every capability call must be cryptographically signed by the caller agent using **ATP-SIG/1**, present valid **ATC/1.0** credentials, comply with **APL/1.0** policy rules, and undergo real-time risk assessment.
3. **Fail-Closed on Inactive Lifecycles**:
   If a caller agent or target agent is `SUSPENDED` or `RETIRED`, resolution and invocation are rejected immediately without fallback.
4. **Strict Environment Isolation**:
   Sandbox callers cannot resolve or invoke production services without an explicit cross-environment policy. Production callers **strictly never failover to sandbox endpoints**.
5. **No Silent Cross-Agent Failover**:
   Failover routes exclusively among verified endpoints belonging to the designated target service. Fallback to arbitrary or unverified agents is strictly forbidden.
6. **Loop & Depth Protection**:
   Dynamic cycle detection prevents circular agent call chains ($A \to B \to C \to A$), while bounded call depth limiter mitigates denial-of-service and runaway recursion.
7. **Response Verification**:
   Target agent responses are cryptographically bound to the initiating request ID and verified for payload integrity before returning to the caller.

## Documentation Index
- [Service Registry & Endpoint Verification](./service-registry.md)
- [ATP/1.0 Calling Pipeline & Security](./atp-calling.md)
- [Loop & Depth Protection Specifications](./loop-protection.md)
